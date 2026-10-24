package application

import (
	"fmt"
	"net/netip"
	"strings"
)

// MaxForwardedHops bounds how many elements of X-Forwarded-For are looked at. A
// chain longer than that is not a chain this Gateway knows how to read: it falls back
// to the peer (ADR-0015, rule 3).
const MaxForwardedHops = 32

// ProxyTrust says which peers are reverse proxies whose X-Forwarded-For can be
// believed, and from that finds who the client is (ADR-0015).
//
// The header is written by whoever sent the request: a client can put anything in
// it. So it is read only when the TCP peer is a declared proxy, and then from the
// right, stopping at the first address that is not a declared proxy — the part on the
// left is what the client wrote, and is not read while something on its right says
// otherwise. Whenever there is doubt, the key is the peer's own address, which is what
// a Gateway with no trust declared has always used: never a value the client chose.
//
// The zero value, and a nil *ProxyTrust, trust nobody.
type ProxyTrust struct {
	trusted []netip.Prefix
}

// ParseTrustedProxies reads the value of TRUSTED_PROXY_CIDRS: addresses and CIDR
// networks separated by commas. An empty value trusts nobody. Everything doubtful is
// an error, because a trust that is wider than meant lets a client choose its own key:
// an empty entry, something that is neither address nor network, a network with
// host bits set (192.168.1.5/24 — which one was meant?), and a network of length 0,
// which would be "every peer" (also when written as the IPv4-mapped IPv6 network ::ffff:0:0/96).
func ParseTrustedProxies(list string) (*ProxyTrust, error) {
	if strings.TrimSpace(list) == "" {
		return &ProxyTrust{}, nil
	}
	t := &ProxyTrust{}
	for i, raw := range strings.Split(list, ",") {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			return nil, fmt.Errorf("entry %d is empty (a stray comma?)", i+1)
		}
		p, err := parseTrustedEntry(entry)
		if err != nil {
			return nil, err
		}
		t.trusted = append(t.trusted, p)
	}
	return t, nil
}

func parseTrustedEntry(entry string) (netip.Prefix, error) {
	var p netip.Prefix
	if strings.Contains(entry, "/") {
		var err error
		p, err = netip.ParsePrefix(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is not a CIDR network", entry)
		}
		if p != p.Masked() {
			return netip.Prefix{}, fmt.Errorf("%q has host bits set: write %s for the network, or the address alone for one proxy", entry, p.Masked())
		}
	} else {
		a, err := netip.ParseAddr(entry)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("%q is neither an address nor a CIDR network", entry)
		}
		if a.Zone() != "" {
			return netip.Prefix{}, fmt.Errorf("%q has a zone: write the address without it", entry)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	// An IPv4 network written in IPv6 is the IPv4 network: a peer is compared as IPv4.
	// (Such a prefix is at least a /96: a shorter one clears bits of the ::ffff marker
	// and has host bits set, which was refused above.)
	if p.Addr().Is4In6() {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	if p.Bits() == 0 {
		return netip.Prefix{}, fmt.Errorf("%q trusts every address: that lets any client choose its own key", entry)
	}
	return p, nil
}

// Entries is what is trusted, for the line the Gateway writes when it starts.
func (t *ProxyTrust) Entries() []string {
	if t == nil {
		return nil
	}
	out := make([]string, 0, len(t.trusted))
	for _, p := range t.trusted {
		out = append(out, p.String())
	}
	return out
}

func (t *ProxyTrust) contains(a netip.Addr) bool {
	if t == nil {
		return false
	}
	a = a.WithZone("").Unmap() // a zone never matches a network
	for _, p := range t.trusted {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientKey is the key of the per-address limiters for one request: remoteAddr is
// the request's RemoteAddr, forwardedFor the values of its X-Forwarded-For header
// lines, in order.
func (t *ProxyTrust) ClientKey(remoteAddr string, forwardedFor []string) string {
	peer, ok := parsePeer(remoteAddr)
	if !ok {
		return remoteAddr
	}
	if !t.contains(peer) {
		return addressKey(peer)
	}
	hops := 0
	for i := len(forwardedFor) - 1; i >= 0; i-- {
		rest := forwardedFor[i]
		for {
			cut := strings.LastIndexByte(rest, ',')
			hops++
			if hops > MaxForwardedHops {
				return addressKey(peer)
			}
			a, ok := parseForwarded(rest[cut+1:])
			if !ok {
				return addressKey(peer)
			}
			if !t.contains(a) {
				return addressKey(a)
			}
			if cut < 0 {
				break
			}
			rest = rest[:cut]
		}
	}
	return addressKey(peer)
}

// parsePeer reads RemoteAddr: "ip:port", "[ipv6]:port" or, failing that, a bare address.
func parsePeer(s string) (netip.Addr, bool) {
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	if a, err := netip.ParseAddr(s); err == nil {
		return a, true
	}
	return netip.Addr{}, false
}

// parseForwarded reads one element of X-Forwarded-For: an address, which some
// proxies write with a port or, for IPv6, in brackets.
func parseForwarded(s string) (netip.Addr, bool) {
	s = strings.TrimSpace(s)
	if a, err := netip.ParseAddr(s); err == nil {
		return a, true
	}
	if ap, err := netip.ParseAddrPort(s); err == nil {
		return ap.Addr(), true
	}
	if len(s) > 2 && s[0] == '[' && s[len(s)-1] == ']' {
		if a, err := netip.ParseAddr(s[1 : len(s)-1]); err == nil {
			return a, true
		}
	}
	return netip.Addr{}, false
}

// addressKey is what an address is called by the limiters (ADR-0015, rule 4): an IPv4
// address written in IPv6 is the IPv4 address, a zone is dropped, and an IPv6 address
// is its /64 — one subscriber owns 2^64 of them, and a bucket per address would hand
// over a new key at will.
func addressKey(a netip.Addr) string {
	a = a.WithZone("").Unmap()
	if a.Is6() {
		return netip.PrefixFrom(a, 64).Masked().String()
	}
	return a.String()
}

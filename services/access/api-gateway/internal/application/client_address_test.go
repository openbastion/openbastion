package application_test

// Who "the client" is behind a reverse proxy, and what the per-address limits are called
// by (ADR-0015). The header is written by whoever sent the request: what these tests pin
// is that no client can choose its own key.

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
)

func trusting(t *testing.T, list string) *application.ProxyTrust {
	t.Helper()
	p, err := application.ParseTrustedProxies(list)
	if err != nil {
		t.Fatalf("ParseTrustedProxies(%q): %v", list, err)
	}
	return p
}

func TestProxyTrust_WhenNobodyIsDeclared_TheHeaderIsNeverRead(t *testing.T) {
	forged := []string{"6.6.6.6", "6.6.6.6, 7.7.7.7"}
	for name, trust := range map[string]*application.ProxyTrust{
		"the zero value": {},
		"nil":            nil,
		"an empty list":  trusting(t, ""),
		"blanks":         trusting(t, "  \t "),
	} {
		t.Run(name, func(t *testing.T) {
			if got := trust.ClientKey("10.0.0.2:4000", forged); got != "10.0.0.2" {
				t.Fatalf("key = %q, want the peer 10.0.0.2: with nobody declared, X-Forwarded-For is not read", got)
			}
			if got := trust.ClientKey("[2001:db8:1:2::9]:4000", forged); got != "2001:db8:1:2::/64" {
				t.Fatalf("key = %q, want the /64 of the peer", got)
			}
		})
	}
	if e := trusting(t, "").Entries(); len(e) != 0 {
		t.Fatalf("Entries() = %v, want none", e)
	}
	if e := (*application.ProxyTrust)(nil).Entries(); len(e) != 0 {
		t.Fatalf("Entries() of nil = %v, want none", e)
	}
}

func TestProxyTrust_FromADeclaredProxy_TheClientIsTheFirstAddressThatIsNotOne(t *testing.T) {
	trust := trusting(t, "10.0.0.0/8, 192.168.5.7, 2001:db8:ffff::/48")
	for _, c := range []struct {
		name string
		peer string
		xff  []string
		want string
	}{
		{"one client", "10.0.0.2:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"a second proxy in the chain", "10.0.0.2:4000", []string{"203.0.113.9, 10.0.0.3"}, "203.0.113.9"},
		{"two proxies in the chain", "10.0.0.2:4000", []string{"203.0.113.9, 10.1.1.1, 192.168.5.7"}, "203.0.113.9"},
		{"what the client wrote on the left is not read", "10.0.0.2:4000", []string{"6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"nor a whole forged chain", "10.0.0.2:4000", []string{"6.6.6.6, 7.7.7.7, 8.8.8.8, 203.0.113.9"}, "203.0.113.9"},
		{"nor a forged proxy on the left", "10.0.0.2:4000", []string{"10.9.9.9, 6.6.6.6, 203.0.113.9"}, "203.0.113.9"},
		{"a proxy forged next to the real client changes nothing", "10.0.0.2:4000", []string{"203.0.113.9, 10.0.0.77"}, "203.0.113.9"},
		{"several header lines are one chain, in order", "10.0.0.2:4000", []string{"6.6.6.6", "203.0.113.9, 10.0.0.3"}, "203.0.113.9"},
		{"the last line is the one the proxy added", "10.0.0.2:4000", []string{"203.0.113.9", "198.51.100.4"}, "198.51.100.4"},
		{"a last line that is only proxies sends the walk to the line before", "10.0.0.2:4000", []string{"203.0.113.9", "10.0.0.3"}, "203.0.113.9"},
		{"three lines, the client on the first", "10.0.0.2:4000", []string{"203.0.113.9", "10.0.0.3, 10.0.0.4", "10.0.0.5"}, "203.0.113.9"},
		{"three lines, a forged first line behind the real one", "10.0.0.2:4000", []string{"6.6.6.6", "203.0.113.9", "10.0.0.5"}, "203.0.113.9"},
		{"a port is dropped", "10.0.0.2:4000", []string{"203.0.113.9:51000"}, "203.0.113.9"},
		{"spaces are dropped", "10.0.0.2:4000", []string{"  203.0.113.9  ,   10.0.0.3 "}, "203.0.113.9"},
		{"an IPv6 client is its /64", "10.0.0.2:4000", []string{"2001:db8:1:2:aaaa:bbbb:cccc:dddd"}, "2001:db8:1:2::/64"},
		{"an IPv6 client in brackets, with a port", "10.0.0.2:4000", []string{"[2001:db8:1:2::5]:443"}, "2001:db8:1:2::/64"},
		{"an IPv6 client in brackets", "10.0.0.2:4000", []string{"[2001:db8:1:2::5]"}, "2001:db8:1:2::/64"},
		{"a proxy that is IPv6", "[2001:db8:ffff::1]:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"a declared single address", "192.168.5.7:4000", []string{"203.0.113.9"}, "203.0.113.9"},
		{"every element is a proxy: the peer", "10.0.0.2:4000", []string{"10.0.0.3, 10.0.0.4"}, "10.0.0.2"},
		{"no header from a proxy: the peer", "10.0.0.2:4000", nil, "10.0.0.2"},
		{"an empty header from a proxy: the peer", "10.0.0.2:4000", []string{""}, "10.0.0.2"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := trust.ClientKey(c.peer, c.xff); got != c.want {
				t.Fatalf("ClientKey(%q, %q) = %q, want %q", c.peer, c.xff, got, c.want)
			}
		})
	}
}

// Believing the header from the wrong peer is the whole attack: the client sends it
// itself, a new value with each request, and the limit it was meant to be under is gone.
func TestProxyTrust_FromAPeerThatIsNotDeclared_TheHeaderIsIgnored(t *testing.T) {
	trust := trusting(t, "10.0.0.0/8, 192.168.5.7, 2001:db8:ffff::/48")
	for _, c := range []struct {
		name, peer, want string
	}{
		{"a stranger", "203.0.113.9:4000", "203.0.113.9"},
		{"just below the network", "9.255.255.255:4000", "9.255.255.255"},
		{"just above the network", "11.0.0.0:4000", "11.0.0.0"},
		{"a neighbour of the declared address", "192.168.5.8:4000", "192.168.5.8"},
		{"the declared address, one before", "192.168.5.6:4000", "192.168.5.6"},
		{"outside the IPv6 network", "[2001:db8:fffe::1]:4000", "2001:db8:fffe::/64"},
		{"a loopback, which nobody declared", "127.0.0.1:4000", "127.0.0.1"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, forged := range [][]string{{"6.6.6.6"}, {"6.6.6.6, 10.0.0.1"}, {"10.0.0.1"}, {"6.6.6.6", "7.7.7.7"}} {
				if got := trust.ClientKey(c.peer, forged); got != c.want {
					t.Fatalf("with X-Forwarded-For %q from %s: key = %q, want the peer %q", forged, c.peer, got, c.want)
				}
			}
		})
	}
	for _, inside := range []string{"10.0.0.0:1", "10.255.255.255:1", "10.9.9.9:1", "192.168.5.7:1", "[2001:db8:ffff::1]:1", "[2001:db8:ffff:ffff:ffff:ffff:ffff:ffff]:1"} {
		if got := trust.ClientKey(inside, []string{"203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("a proxy at %s was not believed: key = %q", inside, got)
		}
	}
}

func TestProxyTrust_AnythingDoubtfulFallsBackToThePeer_NeverToWhatTheClientWrote(t *testing.T) {
	trust := trusting(t, "10.0.0.0/8")
	const peer = "10.0.0.2:4000"
	for _, c := range []struct {
		name string
		xff  []string
	}{
		{"an element that is not an address, reached first", []string{"203.0.113.9, not-an-address"}},
		{"an empty element, reached first", []string{"203.0.113.9, "}},
		{"a name", []string{"203.0.113.9, bastion.example.com"}},
		{"an element that is not an address, behind a proxy", []string{"203.0.113.9, junk, 10.0.0.3"}},
		{"an unterminated bracket", []string{"203.0.113.9, [2001:db8::1"}},
		{"an address with a mask", []string{"203.0.113.9, 203.0.113.0/24"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := trust.ClientKey(peer, c.xff); got != "10.0.0.2" {
				t.Fatalf("ClientKey(%q) = %q, want the peer 10.0.0.2: an element that cannot be read stops the walk, and the walk does not go on to what is on its left", c.xff, got)
			}
		})
	}
	// What is on the left of the first address that is not a proxy is never looked at, so
	// it cannot be a reason to fall back either.
	if got := trust.ClientKey(peer, []string{"junk, \x00, ::::, 203.0.113.9"}); got != "203.0.113.9" {
		t.Fatalf("junk on the left of the client changed the answer: %q", got)
	}

	t.Run("a chain longer than the bound is not read", func(t *testing.T) {
		proxies := func(n int) string { return strings.TrimSuffix(strings.Repeat("10.0.0.9, ", n), ", ") }
		// The client is the Nth element from the right: it is found while N is within the bound.
		within := "203.0.113.9, " + proxies(application.MaxForwardedHops-1)
		if got := trust.ClientKey(peer, []string{within}); got != "203.0.113.9" {
			t.Fatalf("a client at hop %d: key = %q, want it found", application.MaxForwardedHops, got)
		}
		beyond := "203.0.113.9, " + proxies(application.MaxForwardedHops)
		if got := trust.ClientKey(peer, []string{beyond}); got != "10.0.0.2" {
			t.Fatalf("a client at hop %d: key = %q, want the peer: the chain is longer than the bound", application.MaxForwardedHops+1, got)
		}
		// The same bound over several lines, and a header that is enormous.
		lines := make([]string, application.MaxForwardedHops+1)
		for i := range lines {
			lines[i] = "10.0.0.9"
		}
		lines[0] = "203.0.113.9"
		if got := trust.ClientKey(peer, lines); got != "10.0.0.2" {
			t.Fatalf("%d lines: key = %q, want the peer", len(lines), got)
		}
		if got := trust.ClientKey(peer, []string{strings.Repeat("10.0.0.9,", 100000) + "203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("a client on the right of a huge header: key = %q", got)
		}
		if got := trust.ClientKey(peer, []string{"203.0.113.9" + strings.Repeat(",10.0.0.9", 100000)}); got != "10.0.0.2" {
			t.Fatalf("a huge chain of proxies: key = %q, want the peer", got)
		}
	})
}

func TestProxyTrust_KeysAreNormalized(t *testing.T) {
	trust := trusting(t, "10.0.0.0/8")
	t.Run("an IPv4 address written in IPv6 is the IPv4 address", func(t *testing.T) {
		if got := trust.ClientKey("10.0.0.2:1", []string{"::ffff:203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("key = %q", got)
		}
		if got := (&application.ProxyTrust{}).ClientKey("[::ffff:203.0.113.9]:1", nil); got != "203.0.113.9" {
			t.Fatalf("key of a mapped peer = %q", got)
		}
	})
	t.Run("a proxy is a proxy whichever way its address is written", func(t *testing.T) {
		if got := trust.ClientKey("[::ffff:10.0.0.2]:1", []string{"203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("a mapped proxy was not believed: key = %q", got)
		}
		if got := trust.ClientKey("10.0.0.2:1", []string{"203.0.113.9, ::ffff:10.0.0.3"}); got != "203.0.113.9" {
			t.Fatalf("a mapped proxy in the chain was not skipped: key = %q", got)
		}
	})
	t.Run("an IPv6 address is its /64: one subscriber owns 2^64 of them", func(t *testing.T) {
		a := trust.ClientKey("10.0.0.2:1", []string{"2001:db8:1:2:0:0:0:1"})
		b := trust.ClientKey("10.0.0.2:1", []string{"2001:db8:1:2:ffff:ffff:ffff:ffff"})
		c := trust.ClientKey("10.0.0.2:1", []string{"2001:db8:1:3::1"})
		if a != "2001:db8:1:2::/64" || a != b {
			t.Fatalf("two addresses of one /64 are %q and %q, want the same key", a, b)
		}
		if c == a || c != "2001:db8:1:3::/64" {
			t.Fatalf("the next /64 is %q, want its own key", c)
		}
	})
	t.Run("a zone is dropped", func(t *testing.T) {
		if got := trust.ClientKey("10.0.0.2:1", []string{"fe80::1%eth0"}); got != "fe80::/64" {
			t.Fatalf("key = %q", got)
		}
	})
	t.Run("a zone does not keep a proxy from being one", func(t *testing.T) {
		link := trusting(t, "fe80::/10")
		if got := link.ClientKey("[fe80::1%eth0]:1234", []string{"203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("a proxy on a link-local address with a zone was not believed: key = %q", got)
		}
		if got := link.ClientKey("10.0.0.2:1", []string{"fe80::9%eth0"}); got != "10.0.0.2" {
			t.Fatalf("a header from a peer that is not a proxy was read: key = %q", got)
		}
		if got := link.ClientKey("[fe80::1]:1234", []string{"203.0.113.9, fe80::2%eth0"}); got != "203.0.113.9" {
			t.Fatalf("a proxy with a zone in the chain was not skipped: key = %q", got)
		}
	})
	t.Run("an IPv4 key and an IPv6 key never meet", func(t *testing.T) {
		if v4, v6 := trust.ClientKey("10.0.0.2:1", []string{"0.0.0.1"}), trust.ClientKey("10.0.0.2:1", []string{"::1"}); v4 == v6 {
			t.Fatalf("%q and %q are the same key", v4, v6)
		}
	})
	t.Run("a peer that is not an address is used as it is", func(t *testing.T) {
		if got := trust.ClientKey("@", []string{"203.0.113.9"}); got != "@" {
			t.Fatalf("key = %q, want the raw RemoteAddr", got)
		}
	})
	t.Run("a bare address is a peer too", func(t *testing.T) {
		if got := trust.ClientKey("203.0.113.9", nil); got != "203.0.113.9" {
			t.Fatalf("key = %q", got)
		}
		// Written without a port it is still an address: normalized, and a proxy if it is declared.
		if got := trust.ClientKey("2001:db8:1:2::9", nil); got != "2001:db8:1:2::/64" {
			t.Fatalf("a bare IPv6 peer: key = %q, want its /64", got)
		}
		if got := trust.ClientKey("::ffff:203.0.113.9", nil); got != "203.0.113.9" {
			t.Fatalf("a bare mapped peer: key = %q, want the IPv4 address", got)
		}
		if got := trust.ClientKey("10.0.0.2", []string{"203.0.113.9"}); got != "203.0.113.9" {
			t.Fatalf("a bare declared proxy was not believed: key = %q", got)
		}
	})
}

func TestParseTrustedProxies_AcceptsAddressesAndNetworks(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"10.0.0.1", "10.0.0.1/32"},
		{" 10.0.0.1 , 172.16.0.0/12 ", "10.0.0.1/32 172.16.0.0/12"},
		{"2001:db8::/32", "2001:db8::/32"},
		{"2001:db8::1", "2001:db8::1/128"},
		{"10.0.0.0/8,10.0.0.0/8", "10.0.0.0/8 10.0.0.0/8"},
		{"::ffff:10.0.0.1", "10.0.0.1/32"},
		{"::ffff:10.0.0.0/104", "10.0.0.0/8"},
		{"0.0.0.0/1", "0.0.0.0/1"},
		{"::/1", "::/1"},
		{"192.168.0.0/16, fd00::/8", "192.168.0.0/16 fd00::/8"},
	} {
		t.Run(c.in, func(t *testing.T) {
			p, err := application.ParseTrustedProxies(c.in)
			if err != nil {
				t.Fatal(err)
			}
			if got := strings.Join(p.Entries(), " "); got != c.want {
				t.Fatalf("Entries() = %q, want %q", got, c.want)
			}
		})
	}
}

// A trust wider than meant lets a client choose its own key, so every doubt is an error
// that stops the Gateway, naming the entry — and none of them is a value that means "everyone".
func TestParseTrustedProxies_EveryDoubtIsAnError(t *testing.T) {
	for _, c := range []struct {
		in   string
		want string
	}{
		{"0.0.0.0/0", "trusts every address"},
		{"::/0", "trusts every address"},
		{"::ffff:0.0.0.0/96", "trusts every address"},
		{"::ffff:0:0/96", "trusts every address"},
		{"10.0.0.0/8,0.0.0.0/0", "trusts every address"},
		{"10.0.0.0/8,,172.16.0.0/12", "entry 2 is empty"},
		{"10.0.0.0/8,", "entry 2 is empty"},
		{",10.0.0.0/8", "entry 1 is empty"},
		{"10.0.0.0/8,   ,172.16.0.0/12", "entry 2 is empty"},
		{"banana", `"banana" is neither an address nor a CIDR network`},
		{"10.0.0.0/8 172.16.0.0/12", "is not a CIDR network"},
		{"10.0.0.1 10.0.0.2", "is neither an address nor a CIDR network"},
		{"10.0.0.0/33", "is not a CIDR network"},
		{"10.0.0.0/-1", "is not a CIDR network"},
		{"10.0.0.0/abc", "is not a CIDR network"},
		{"2001:db8::/129", "is not a CIDR network"},
		{"10.0.0.256", "is neither an address nor a CIDR network"},
		{"fe80::1%eth0", "has a zone"},
		{"192.168.1.5/24", "has host bits set: write 192.168.1.0/24"},
		{"10.0.0.1/8", "has host bits set"},
		{"2001:db8::1/32", "has host bits set"},
		{"::ffff:0:0/80", "has host bits set"},
		{"::ffff:10.0.0.0/64", "has host bits set"},
	} {
		t.Run(c.in, func(t *testing.T) {
			p, err := application.ParseTrustedProxies(c.in)
			if err == nil {
				t.Fatalf("accepted %q (%v), want an error", c.in, p.Entries())
			}
			if !strings.Contains(err.Error(), c.want) {
				t.Fatalf("error for %q = %q, want it to say %q", c.in, err, c.want)
			}
			if p != nil {
				t.Fatalf("a trust was returned along with the error")
			}
		})
	}
}

// Making the per-address limits adjustable must relax nothing: what the limiters have
// always really done is what they do until someone asks, by name, for something else.
func TestPerAddressLimiters_TheDefaultsAreWhatTheyAlwaysReallyDid(t *testing.T) {
	if application.DefaultLoginBurst != 5 || application.DefaultLoginRatePerMinute != 1 ||
		application.DefaultClientRequestBurst != 60 || application.DefaultClientRequestRatePerMinute != 60 {
		t.Fatalf("the defaults are login %d then %d a minute, requests %d then %d a minute; they were 5 then 1 and 60 then 60",
			application.DefaultLoginBurst, application.DefaultLoginRatePerMinute,
			application.DefaultClientRequestBurst, application.DefaultClientRequestRatePerMinute)
	}
	if application.MaxLoginBurst != 100 || application.MaxLoginRatePerMinute != 60 ||
		application.MaxClientRequestBurst != 10000 || application.MaxClientRequestRatePerMinute != 6000 {
		t.Fatal("the bounds are not the documented ones (100, 60, 10000, 6000)")
	}

	// run spends the burst, notes how long a refused request is told to wait, checks that
	// the first token comes back exactly then (and not a moment before), and then lets a
	// whole minute pass to see how many the bucket holds again.
	run := func(t *testing.T, l *application.RateLimiter, clock *fakeClock) (burst int, wait time.Duration, afterAMinute int) {
		for l.Allow("k") {
			burst++
		}
		wait = l.Take("k").RetryAfter
		clock.Advance(wait - time.Millisecond)
		if l.Allow("k") {
			t.Fatalf("a token came back %v early", time.Millisecond)
		}
		clock.Advance(time.Millisecond)
		if !l.Allow("k") {
			t.Fatalf("no token after the %v it was told to wait", wait)
		}
		clock.Advance(time.Minute)
		for l.Allow("k") {
			afterAMinute++
		}
		return
	}
	for _, c := range []struct {
		name         string
		build        func(clock *fakeClock) *application.RateLimiter
		burst        int
		wait         time.Duration
		afterAMinute int
	}{
		{"login, built by hand: the strict default", func(c *fakeClock) *application.RateLimiter { return application.NewLoginLimiter(0, 0).WithClock(c.Now) }, 5, time.Minute, 1},
		{"login, negative: the strict default", func(c *fakeClock) *application.RateLimiter {
			return application.NewLoginLimiter(-3, -3).WithClock(c.Now)
		}, 5, time.Minute, 1},
		{"requests, built by hand: the strict default", func(c *fakeClock) *application.RateLimiter {
			return application.NewClientRequestLimiter(0, 0).WithClock(c.Now)
		}, 60, time.Second, 60},
		{"login, asked for: 2 then 30 a minute (the bucket holds 2)", func(c *fakeClock) *application.RateLimiter {
			return application.NewLoginLimiter(2, 30).WithClock(c.Now)
		}, 2, 2 * time.Second, 2},
		{"requests, asked for: 100 then 30 a minute", func(c *fakeClock) *application.RateLimiter {
			return application.NewClientRequestLimiter(100, 30).WithClock(c.Now)
		}, 100, 2 * time.Second, 30}, // a minute is worth 30 tokens
		{"requests, asked for: 7 then 120 a minute", func(c *fakeClock) *application.RateLimiter {
			return application.NewClientRequestLimiter(7, 120).WithClock(c.Now)
		}, 7, 500 * time.Millisecond, 7},
		{"login, only the burst asked for: the rate stays strict", func(c *fakeClock) *application.RateLimiter {
			return application.NewLoginLimiter(9, 0).WithClock(c.Now)
		}, 9, time.Minute, 1},
		{"login, only the rate asked for: the burst stays strict", func(c *fakeClock) *application.RateLimiter {
			return application.NewLoginLimiter(0, 12).WithClock(c.Now)
		}, 5, 5 * time.Second, 5}, // a minute is worth 12 tokens, but the bucket holds 5
	} {
		t.Run(c.name, func(t *testing.T) {
			clock := newFakeClock()
			burst, wait, afterAMinute := run(t, c.build(clock), clock)
			if burst != c.burst {
				t.Fatalf("burst = %d, want %d", burst, c.burst)
			}
			if wait != c.wait {
				t.Fatalf("a refused request is told to wait %v, want %v", wait, c.wait)
			}
			if afterAMinute != c.afterAMinute {
				t.Fatalf("a minute later, %d requests pass, want %d", afterAMinute, c.afterAMinute)
			}
		})
	}
	// The same three constructors, side by side: one does not borrow the defaults of another.
	l, r, s := application.NewLoginLimiter(0, 0), application.NewClientRequestLimiter(0, 0), application.NewSessionRequestLimiter(0, 0)
	if fmt.Sprint(l.Capacity(), r.Capacity(), s.Capacity()) != "5 60 10" {
		t.Fatalf("capacities %d, %d, %d: want 5, 60, 10", l.Capacity(), r.Capacity(), s.Capacity())
	}
	if fmt.Sprint(l.Refill(), r.Refill(), s.Refill()) != "1m0s 1s 10s" {
		t.Fatalf("refills %v, %v, %v: want 1m0s, 1s, 10s", l.Refill(), r.Refill(), s.Refill())
	}
}

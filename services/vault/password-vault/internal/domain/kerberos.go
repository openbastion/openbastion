package domain

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
)

// The Kerberos settings of an RDP account (ADR-0100): the realm of the account and the KDCs the
// proxy reaches for its tickets. They are the account's administrator's, never the operator's; the
// KDCs are explicit, never discovered in DNS. The service principal is not stored: it is
// TERMSRV/<the account's pinned target name> (ADR-0071), the name the target's certificate is
// verified against, so a ticket is only ever asked for the target the secret is sent to.

// MaxKerberosKDCs bounds the KDCs of an account, as pkg/rdp does.
const MaxKerberosKDCs = 4

// ErrInvalidKerberos: settings outside ADR-0100's bounds.
var ErrInvalidKerberos = errors.New("invalid Kerberos settings")

type KerberosSettings struct {
	// Realm is the account's realm, in upper case (an Active Directory domain's DNS name).
	Realm string `json:"realm"`
	// KDCs are the realm's KDCs, host:port, one to four; the port is 88 when not given.
	KDCs []string `json:"kdcs"`
}

// Normalized checks the settings and returns them in canonical form: the realm in upper case,
// each KDC as host:port with its host in lower case, without a duplicate.
func (k KerberosSettings) Normalized() (KerberosSettings, error) {
	realm := strings.ToUpper(strings.TrimSpace(k.Realm))
	if !validDNSName(strings.ToLower(realm)) {
		return KerberosSettings{}, fmt.Errorf("%w: realm %q", ErrInvalidKerberos, k.Realm)
	}
	if len(k.KDCs) == 0 || len(k.KDCs) > MaxKerberosKDCs {
		return KerberosSettings{}, fmt.Errorf("%w: one to %d KDCs", ErrInvalidKerberos, MaxKerberosKDCs)
	}
	out := KerberosSettings{Realm: realm, KDCs: make([]string, 0, len(k.KDCs))}
	seen := map[string]bool{}
	for _, raw := range k.KDCs {
		kdc, err := normalizeKDC(raw)
		if err != nil {
			return KerberosSettings{}, err
		}
		if seen[kdc] {
			return KerberosSettings{}, fmt.Errorf("%w: KDC %q twice", ErrInvalidKerberos, kdc)
		}
		seen[kdc] = true
		out.KDCs = append(out.KDCs, kdc)
	}
	return out, nil
}

// normalizeKDC accepts host or host:port, the host a DNS name or an IP literal (IPv6 in brackets
// when a port is given), never a URL, a wildcard or a port out of range.
func normalizeKDC(raw string) (string, error) {
	value := strings.TrimSpace(raw)
	host, port := value, "88"
	// Without a port, the whole value is the host: a stray colon then fails the host check below.
	if h, p, err := net.SplitHostPort(value); err == nil {
		host, port = h, p
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
		return "", fmt.Errorf("%w: KDC %q: port", ErrInvalidKerberos, raw)
	}
	if ip := net.ParseIP(host); ip != nil {
		return net.JoinHostPort(ip.String(), port), nil
	}
	host = strings.TrimSuffix(strings.ToLower(host), ".")
	if !validDNSName(host) {
		return "", fmt.Errorf("%w: KDC %q: host", ErrInvalidKerberos, raw)
	}
	return net.JoinHostPort(host, port), nil
}

// validDNSName: lower-case ASCII labels of 1 to 63 letters, digits and inner hyphens, 253 at most.
func validDNSName(name string) bool {
	if name == "" || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

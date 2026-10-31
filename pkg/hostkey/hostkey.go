// Package hostkey is how OpenBastion recognises an SSH target before sending it a secret: by
// the exact host key pinned to the account (ADR-0039), or by the certificate authority pinned
// to it, for one host name (ADR-0048). The Vault reads and stores the line; the Vault's rotation
// and the SSH proxy verify the target with it. One implementation for both, so that the two
// places that hand out a secret can never disagree about whom they hand it to.
package hostkey

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// AuthorityMarker starts a stored authority line, as in known_hosts.
const AuthorityMarker = "@cert-authority"

// MaxNameBytes bounds the host name an authority's certificate must carry.
const MaxNameBytes = 253

// ErrBadLine: what was given is neither one public key nor one authority line.
var ErrBadLine = errors.New("not an SSH host key (\"ssh-ed25519 AAAA…\") nor an authority line (\"@cert-authority host.example ssh-ed25519 AAAA…\")")

// ErrMismatch wraps every refusal of a target: nothing is sent to it.
var ErrMismatch = errors.New("the target is not the one this account recognises")

// Trust is what an account recognises its target by: a pinned key, or an authority and a name.
type Trust struct {
	pinned    ssh.PublicKey
	authority ssh.PublicKey
	name      string
}

// Normalize reads what an administrator gives and returns the line to store and the fingerprint
// to show (the authority's, for an authority line). A key is "type base64 [comment]", as in a .pub
// file, or a known_hosts line whose host names are dropped. An authority line is
// "@cert-authority <one host name or address> <key>". Anything else is ErrBadLine: two lines, a
// @revoked line, a pattern or a list for the name, a port, a key that does not read.
func Normalize(s string) (line, fingerprint string, err error) {
	t, err := parse(s)
	if err != nil {
		return "", "", err
	}
	return t.String(), t.Fingerprint(), nil
}

// Parse reads a stored line (what Normalize returned).
func Parse(line string) (Trust, error) { return parse(line) }

func parse(s string) (Trust, error) {
	line := strings.TrimSpace(s)
	if line == "" || strings.ContainsAny(line, "\r\n") {
		return Trust{}, ErrBadLine
	}
	if !strings.HasPrefix(line, "@") {
		pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return Trust{}, ErrBadLine
		}
		if _, isCert := pub.(*ssh.Certificate); isCert {
			return Trust{}, ErrBadLine // a certificate is what a target presents, not what an account pins
		}
		return Trust{pinned: pub}, nil
	}
	fields := strings.Fields(line)
	if len(fields) < 3 || fields[0] != AuthorityMarker {
		return Trust{}, ErrBadLine
	}
	name := strings.ToLower(fields[1])
	if !validName(name) {
		return Trust{}, ErrBadLine
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.Join(fields[2:], " ")))
	if err != nil {
		return Trust{}, ErrBadLine
	}
	if _, isCert := pub.(*ssh.Certificate); isCert {
		return Trust{}, ErrBadLine
	}
	return Trust{authority: pub, name: name}, nil
}

// validName: one host name or address — letters, digits, '.', '-', and ':' for IPv6 — no pattern,
// no list, no brackets nor port.
func validName(n string) bool {
	if n == "" || len(n) > MaxNameBytes {
		return false
	}
	for _, c := range n {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '.' || c == '-' || c == ':') {
			return false
		}
	}
	if strings.Contains(n, ":") && net.ParseIP(n) == nil {
		return false // a colon is only an IPv6 address, never host:port
	}
	return true
}

// IsAuthority says whether the account recognises its target by an authority.
func (t Trust) IsAuthority() bool { return t.authority != nil }

// Name is the host name an authority's certificate must carry ("" for a pinned key).
func (t Trust) Name() string { return t.name }

// String is the line to store.
func (t Trust) String() string {
	if t.authority != nil {
		return AuthorityMarker + " " + t.name + " " + marshal(t.authority)
	}
	if t.pinned != nil {
		return marshal(t.pinned)
	}
	return ""
}

// Fingerprint is the SHA256 fingerprint of the pinned key, or of the authority.
func (t Trust) Fingerprint() string {
	switch {
	case t.authority != nil:
		return ssh.FingerprintSHA256(t.authority)
	case t.pinned != nil:
		return ssh.FingerprintSHA256(t.pinned)
	}
	return ""
}

func marshal(k ssh.PublicKey) string { return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) }

// authorityAlgorithms are the host key algorithms offered to a target recognised by an
// authority: certificates first, so that a certified target sends its certificate; then plain
// keys, so that a target without one reaches the verification — and is refused there, said and
// audited as a host key mismatch, rather than lost in a negotiation failure. No SHA-1 RSA.
var authorityAlgorithms = []string{
	ssh.CertAlgoED25519v01, ssh.CertAlgoECDSA256v01, ssh.CertAlgoECDSA384v01, ssh.CertAlgoECDSA521v01,
	ssh.CertAlgoRSASHA512v01, ssh.CertAlgoRSASHA256v01,
	ssh.KeyAlgoED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384, ssh.KeyAlgoECDSA521,
	ssh.KeyAlgoRSASHA512, ssh.KeyAlgoRSASHA256,
}

// Configure sets the host key verification of an SSH client config: exactly the pinned key, or a
// certificate of the authority for its name. now is the clock a certificate's validity is read
// against (time.Now when nil).
func (t Trust) Configure(c *ssh.ClientConfig, now func() time.Time) {
	if now == nil {
		now = time.Now
	}
	if t.IsAuthority() {
		c.HostKeyAlgorithms = append([]string(nil), authorityAlgorithms...)
	}
	c.HostKeyCallback = t.callback(now)
}

func (t Trust) callback(now func() time.Time) ssh.HostKeyCallback {
	return func(hostname string, _ net.Addr, key ssh.PublicKey) error {
		if t.pinned != nil {
			if bytes.Equal(key.Marshal(), t.pinned.Marshal()) {
				return nil
			}
			return fmt.Errorf("%w: %s presented %s, pinned %s", ErrMismatch, hostname, ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(t.pinned))
		}
		if t.authority == nil {
			return fmt.Errorf("%w: the account recognises no key and no authority", ErrMismatch)
		}
		return t.checkCertificate(hostname, key, now())
	}
}

func (t Trust) checkCertificate(hostname string, key ssh.PublicKey, at time.Time) error {
	cert, ok := key.(*ssh.Certificate)
	if !ok {
		return fmt.Errorf("%w: %s presented a plain key %s, the account recognises certificates of authority %s for %s",
			ErrMismatch, hostname, ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(t.authority), t.name)
	}
	if cert.CertType != ssh.HostCert {
		return fmt.Errorf("%w: %s presented a user certificate", ErrMismatch, hostname)
	}
	if !bytes.Equal(cert.SignatureKey.Marshal(), t.authority.Marshal()) {
		return fmt.Errorf("%w: %s presented a certificate of authority %s, the account recognises %s",
			ErrMismatch, hostname, ssh.FingerprintSHA256(cert.SignatureKey), ssh.FingerprintSHA256(t.authority))
	}
	// An empty list of names means "any host" to OpenSSH: never for an account.
	if len(cert.ValidPrincipals) == 0 {
		return fmt.Errorf("%w: %s presented a certificate valid for any host name", ErrMismatch, hostname)
	}
	if cert.ValidBefore == ssh.CertTimeInfinity {
		return fmt.Errorf("%w: %s presented a certificate without an end, which nothing could withdraw", ErrMismatch, hostname)
	}
	checker := &ssh.CertChecker{Clock: func() time.Time { return at }}
	// CheckCert verifies the name (in the list), the period, the critical options and the
	// authority's signature over the certificate.
	if err := checker.CheckCert(t.name, cert); err != nil {
		return fmt.Errorf("%w: %s presented a certificate that does not hold for %s: %v", ErrMismatch, hostname, t.name, err)
	}
	return nil
}

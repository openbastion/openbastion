package mtls

import (
	"context"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// material is one consistent snapshot of a service's identity: certificate,
// key and trusted authorities, validated together. Credentials swaps whole
// snapshots, so a handshake never sees a certificate from one rotation and an
// authority bundle from another.
type material struct {
	cert     tls.Certificate
	leaf     *x509.Certificate
	cas      *x509.CertPool
	identity string
	digest   [sha256.Size]byte // of the three files, to notice a change
}

// Credentials is a service's identity, kept fresh. It re-reads its files every
// ReloadInterval (at the next handshake after the delay), so rotating a
// certificate or the authority bundle needs no restart (ADR-0010).
//
// A reload that fails — a torn write, an expired replacement, a certificate for
// another service — keeps the previous snapshot and is logged once. A service
// is never taken down by a bad file; it is only never trusted *less* carefully.
type Credentials struct {
	settings Settings
	now      func() time.Time
	logf     func(format string, args ...any)

	cur       atomic.Pointer[material]
	lastCheck atomic.Int64 // unix nanoseconds
	mu        sync.Mutex   // serialises reloads
	lastBad   [sha256.Size]byte
	warned    atomic.Int32 // 0 none, 1 expiring, 2 expired
}

// NewCredentials loads and validates a service's identity now. It fails if the
// files cannot be read, do not belong together, do not chain to the CA, carry no
// valid identity of the trust domain, or are outside their validity period.
func NewCredentials(s Settings) (*Credentials, error) {
	return newCredentials(s, time.Now, log.Printf)
}

func newCredentials(s Settings, now func() time.Time, logf func(string, ...any)) (*Credentials, error) {
	if s.Mode == Disabled {
		return nil, errors.New("mtls: credentials requested while INTERNAL_TLS=disabled")
	}
	if s.ReloadInterval <= 0 {
		s.ReloadInterval = DefaultReloadInterval
	}
	c := &Credentials{settings: s, now: now, logf: logf}
	m, err := loadMaterial(s, now())
	if err != nil {
		return nil, err
	}
	c.cur.Store(m)
	c.lastCheck.Store(now().UnixNano())
	return c, nil
}

// Identity is the service name this process's certificate vouches for.
func (c *Credentials) Identity() string { return c.cur.Load().identity }

// TrustDomain is the trust domain peers must belong to.
func (c *Credentials) TrustDomain() string { return c.settings.TrustDomain }

// NotAfter is when the certificate currently in use expires.
func (c *Credentials) NotAfter() time.Time { return c.cur.Load().leaf.NotAfter }

func loadMaterial(s Settings, now time.Time) (*material, error) {
	certPEM, err := os.ReadFile(s.CertFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: reading certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(s.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: reading key: %w", err)
	}
	caPEM, err := os.ReadFile(s.CAFile)
	if err != nil {
		return nil, fmt.Errorf("mtls: reading CA bundle: %w", err)
	}

	pair, err := tls.X509KeyPair(certPEM, keyPEM) // fails if the key is not the certificate's
	if err != nil {
		return nil, fmt.Errorf("mtls: certificate and key: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("mtls: parsing certificate: %w", err)
	}
	pair.Leaf = leaf

	cas := x509.NewCertPool()
	if !cas.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("mtls: the CA bundle holds no certificate")
	}

	identity, err := ServiceFromCertificate(leaf, s.TrustDomain)
	if err != nil {
		return nil, err
	}
	if now.Before(leaf.NotBefore) {
		return nil, fmt.Errorf("mtls: certificate for %q is not valid before %s", identity, leaf.NotBefore.UTC().Format(time.RFC3339))
	}
	if now.After(leaf.NotAfter) {
		return nil, fmt.Errorf("mtls: certificate for %q expired at %s", identity, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	if pub, ok := leaf.PublicKey.(*rsa.PublicKey); ok && pub.N.BitLen() < 2048 {
		return nil, fmt.Errorf("mtls: certificate for %q has a %d-bit RSA key; 2048 is the minimum", identity, pub.N.BitLen())
	}

	// A certificate peers would refuse is refused here, where the operator is
	// looking, rather than as a stream of handshake failures later.
	inter := x509.NewCertPool()
	for _, der := range pair.Certificate[1:] {
		if ic, err := x509.ParseCertificate(der); err == nil {
			inter.AddCert(ic)
		}
	}
	for _, usage := range []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth} {
		if _, err := leaf.Verify(x509.VerifyOptions{Roots: cas, Intermediates: inter, KeyUsages: []x509.ExtKeyUsage{usage}, CurrentTime: now}); err != nil {
			return nil, fmt.Errorf("mtls: certificate for %q does not chain to the CA bundle for use as %s: %w", identity, usageName(usage), err)
		}
	}

	h := sha256.New()
	for _, b := range [][]byte{certPEM, keyPEM, caPEM} {
		_, _ = h.Write(b)
		_, _ = h.Write([]byte{0})
	}
	m := &material{cert: pair, leaf: leaf, cas: cas, identity: identity}
	copy(m.digest[:], h.Sum(nil))
	return m, nil
}

func usageName(u x509.ExtKeyUsage) string {
	if u == x509.ExtKeyUsageServerAuth {
		return "a server"
	}
	return "a client"
}

// fileDigest is the digest loadMaterial would compute, without validating —
// the cheap "did anything change" test run on each check.
func fileDigest(s Settings) ([sha256.Size]byte, bool) {
	var d [sha256.Size]byte
	h := sha256.New()
	for _, f := range []string{s.CertFile, s.KeyFile, s.CAFile} {
		b, err := os.ReadFile(f)
		if err != nil {
			return d, false
		}
		_, _ = h.Write(b)
		_, _ = h.Write([]byte{0})
	}
	copy(d[:], h.Sum(nil))
	return d, true
}

// current returns the snapshot to use for a handshake, refreshing it first if
// the reload interval has elapsed.
func (c *Credentials) current() *material {
	if c.now().UnixNano()-c.lastCheck.Load() >= int64(c.settings.ReloadInterval) {
		c.refresh()
	}
	return c.cur.Load()
}

func (c *Credentials) refresh() {
	if !c.mu.TryLock() { // someone is already looking
		return
	}
	defer c.mu.Unlock()
	now := c.now()
	c.lastCheck.Store(now.UnixNano())

	old := c.cur.Load()
	if d, ok := fileDigest(c.settings); ok && d != old.digest && d != c.lastBad {
		m, err := loadMaterial(c.settings, now)
		switch {
		case err != nil:
			c.lastBad = d // say it once per distinct content, not at every check
			c.logf("mtls: NOT reloading the identity of %s, keeping the current one: %v", old.identity, err)
		case m.identity != old.identity:
			c.lastBad = d
			c.logf("mtls: NOT reloading: the new certificate is for %q but this process is %q", m.identity, old.identity)
		default:
			c.cur.Store(m)
			c.warned.Store(0)
			old = m
			c.logf("mtls: reloaded the identity of %s (valid until %s)", m.identity, m.leaf.NotAfter.UTC().Format(time.RFC3339))
		}
	}

	// Expiry is an outage for a Tier-0 component (Guide HA): say so before and when it happens.
	lifetime := old.leaf.NotAfter.Sub(old.leaf.NotBefore)
	left := old.leaf.NotAfter.Sub(now)
	switch {
	case left <= 0 && c.warned.Swap(2) != 2:
		c.logf("mtls: the certificate of %s EXPIRED at %s — peers will refuse this service until it is renewed", old.identity, old.leaf.NotAfter.UTC().Format(time.RFC3339))
	case left > 0 && left < lifetime/5 && c.warned.CompareAndSwap(0, 1):
		c.logf("mtls: the certificate of %s expires at %s (%s left) — renew it", old.identity, old.leaf.NotAfter.UTC().Format(time.RFC3339), left.Round(time.Second))
	}
}

// ServerTLS is the configuration for an http.Server: TLS 1.3, a client
// certificate that chains to the CA bundle and carries a valid identity of this
// trust domain — or no connection at all. The configuration is rebuilt per
// handshake from the current snapshot, so rotation takes effect without a restart.
func (c *Credentials) ServerTLS() *tls.Config {
	td := c.settings.TrustDomain
	return &tls.Config{
		// If GetConfigForClient were ever to fail, this fallback still demands a
		// client certificate and has none to give: closed, not open.
		MinVersion: tls.VersionTLS13,
		ClientAuth: tls.RequireAndVerifyClientCert,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			m := c.current()
			return &tls.Config{
				MinVersion:   tls.VersionTLS13,
				Certificates: []tls.Certificate{m.cert},
				ClientAuth:   tls.RequireAndVerifyClientCert,
				ClientCAs:    m.cas,
				NextProtos:   []string{"http/1.1"},
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return ErrNoIdentity
					}
					_, err := ServiceFromCertificate(cs.PeerCertificates[0], td)
					return err
				},
			}, nil
		},
	}
}

// Peer names a service a client will talk to and the identity it must prove.
type Peer struct {
	URL     string // https://host:port
	Service string // the identity the server must present
}

// Client returns an http.Client that can reach exactly the given peers, over
// mutual TLS, and verifies that each answers with the identity it is supposed
// to have. Beyond a valid certificate for the right name or address, the peer's
// *service* identity must match: a compromised service cannot stand in for
// another one, and the Vault never hands a scope token to the wrong party.
//
// It refuses plaintext and any address that is not a registered peer, and it
// ignores HTTP(S)_PROXY — internal traffic never goes through an egress proxy.
func (c *Credentials) Client(peers ...Peer) (*http.Client, error) {
	byAddr := make(map[string]string, len(peers))
	for _, p := range peers {
		u, err := url.Parse(p.URL)
		if err != nil || u.Host == "" {
			return nil, fmt.Errorf("mtls: peer %q has no usable URL %q", p.Service, p.URL)
		}
		if u.Scheme != "https" {
			return nil, fmt.Errorf("mtls: peer %q is reached at %q, but INTERNAL_TLS requires https — fix the URL, or set INTERNAL_TLS=disabled for development", p.Service, p.URL)
		}
		if !ValidServiceName(p.Service) {
			return nil, fmt.Errorf("mtls: %q is not a valid service name", p.Service)
		}
		addr := u.Host
		if u.Port() == "" {
			addr = net.JoinHostPort(u.Hostname(), "443")
		}
		if prev, dup := byAddr[addr]; dup && prev != p.Service {
			return nil, fmt.Errorf("mtls: %s is registered as both %q and %q", addr, prev, p.Service)
		}
		byAddr[addr] = p.Service
	}

	td := c.settings.TrustDomain
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	tr := &http.Transport{
		Proxy: nil,
		DialContext: func(context.Context, string, string) (net.Conn, error) {
			return nil, errors.New("mtls: refusing a plaintext connection between services")
		},
		DialTLSContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			want, ok := byAddr[addr]
			if !ok {
				return nil, fmt.Errorf("mtls: %s is not a registered peer of this service", addr)
			}
			host, _, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			m := c.current()
			cfg := &tls.Config{
				MinVersion:   tls.VersionTLS13,
				ServerName:   host,
				RootCAs:      m.cas,
				Certificates: []tls.Certificate{m.cert},
				NextProtos:   []string{"http/1.1"},
				VerifyConnection: func(cs tls.ConnectionState) error {
					if len(cs.PeerCertificates) == 0 {
						return ErrNoIdentity
					}
					got, err := ServiceFromCertificate(cs.PeerCertificates[0], td)
					if err != nil {
						return err
					}
					if got != want {
						return fmt.Errorf("mtls: %s answered as %q, expected %q", addr, got, want)
					}
					return nil
				},
			}
			return (&tls.Dialer{NetDialer: dialer, Config: cfg}).DialContext(ctx, network, addr)
		},
		TLSHandshakeTimeout: 5 * time.Second,
		IdleConnTimeout:     30 * time.Second,
		MaxIdleConnsPerHost: 4,
	}
	return &http.Client{Transport: tr}, nil
}

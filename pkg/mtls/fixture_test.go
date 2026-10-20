package mtls_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

const testDomain = "openbastion.test"

// env is a throw-away PKI on disk: a CA and the identities issued from it.
type env struct {
	t   *testing.T
	dir string
	ca  *pki.CA
}

func newEnv(t *testing.T) *env {
	t.Helper()
	ca, err := pki.NewCA(testDomain, 48*time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	e := &env{t: t, dir: t.TempDir(), ca: ca}
	e.writeCA(ca)
	return e
}

func (e *env) writeCA(ca *pki.CA) {
	e.t.Helper()
	must(e.t, os.WriteFile(filepath.Join(e.dir, "ca.pem"), ca.CertPEM(), 0o600))
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// issue writes (or rewrites) the identity of service under the environment and
// returns Settings pointing at it.
func (e *env) issue(service string, opts pki.IssueOptions) mtls.Settings {
	e.t.Helper()
	leaf, err := e.ca.Issue(service, opts)
	must(e.t, err)
	return e.install(service, leaf)
}

func (e *env) install(service string, leaf *pki.Leaf) mtls.Settings {
	e.t.Helper()
	d := filepath.Join(e.dir, service)
	must(e.t, os.MkdirAll(d, 0o700))
	must(e.t, os.WriteFile(filepath.Join(d, "key.pem"), leaf.KeyPEM, 0o600))
	must(e.t, os.WriteFile(filepath.Join(d, "cert.pem"), leaf.CertPEM, 0o600))
	return e.settingsFor(service)
}

func (e *env) settingsFor(service string) mtls.Settings {
	d := filepath.Join(e.dir, service)
	return mtls.Settings{
		Mode:           mtls.Required,
		CertFile:       filepath.Join(d, "cert.pem"),
		KeyFile:        filepath.Join(d, "key.pem"),
		CAFile:         filepath.Join(e.dir, "ca.pem"),
		TrustDomain:    testDomain,
		ReloadInterval: 20 * time.Millisecond,
	}
}

// creds is the live identity of a service.
func (e *env) creds(service string) *mtls.Credentials {
	e.t.Helper()
	c, err := mtls.NewCredentials(e.issue(service, pki.IssueOptions{}))
	must(e.t, err)
	return c
}

// forge signs a certificate with the CA's own key for arbitrary URI SANs —
// the kind of almost-identity a strict verifier must not accept.
func (e *env) forge(uris ...string) tls.Certificate {
	e.t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(e.t, err)
	var us []*url.URL
	for _, s := range uris {
		u, err := url.Parse(s)
		must(e.t, err)
		us = append(us, u)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "forged"},
		NotBefore:    time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour),
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		URIs:        us, DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, e.ca.Cert, &key.PublicKey, e.ca.Key)
	must(e.t, err)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// certFor is the tls.Certificate of an identity issued with explicit options,
// bypassing Credentials' own validation (which would refuse an expired one).
func (e *env) certFor(service string, opts pki.IssueOptions) tls.Certificate {
	e.t.Helper()
	leaf, err := e.ca.Issue(service, opts)
	must(e.t, err)
	pair, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	must(e.t, err)
	return pair
}

func (e *env) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(e.ca.Cert)
	return p
}

// rawClient is a client that does exactly what the test says, no more.
func rawClient(cfg *tls.Config) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: cfg, Proxy: nil, DisableKeepAlives: true}}
}

// server is a Guarded service on a loopback port, recording who got through.
type server struct {
	URL     string
	Addr    string
	mu      sync.Mutex
	hits    []string // "<caller> <method> <path>"
	serials []string // client certificate serial of each request
}

func (s *server) served() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.hits...)
}

// serve starts an HTTP server with creds' TLS configuration and the given rules.
func (e *env) serve(creds *mtls.Credentials, rules []mtls.Rule) *server {
	e.t.Helper()
	s := &server{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		who, _ := mtls.CallerFrom(r.Context())
		s.mu.Lock()
		s.hits = append(s.hits, fmt.Sprintf("%s %s %s", who, r.Method, r.URL.Path))
		if r.TLS != nil && len(r.TLS.PeerCertificates) > 0 {
			s.serials = append(s.serials, r.TLS.PeerCertificates[0].SerialNumber.String())
		}
		s.mu.Unlock()
		_, _ = io.WriteString(w, who)
	})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	must(e.t, err)
	srv := &http.Server{Handler: mtls.Guard(testDomain, rules, h), TLSConfig: creds.ServerTLS()}
	go func() { _ = srv.ServeTLS(ln, "", "") }()
	e.t.Cleanup(func() { _ = srv.Close() })
	s.Addr = ln.Addr().String()
	s.URL = "https://" + s.Addr
	return s
}

func (s *server) lastClientSerial() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.serials) == 0 {
		return ""
	}
	return s.serials[len(s.serials)-1]
}

// serverSerial is the serial of the certificate the server presents to c.
func serverSerial(c *http.Client, url string) (string, error) {
	c.CloseIdleConnections()
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, resp.Body)
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return "", fmt.Errorf("no TLS state")
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.String(), nil
}

// eventually polls until cond holds, failing after a few seconds.
func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for: %s", what)
}

func get(c *http.Client, url string) (int, string, error) {
	return do(c, http.MethodGet, url)
}

func do(c *http.Client, method, url string) (int, string, error) {
	req, err := http.NewRequest(method, url, strings.NewReader(""))
	if err != nil {
		return 0, "", err
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(b)), nil
}

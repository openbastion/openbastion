// Helpers for the mutual-TLS tests (ADR-0010): a PKI minted per test, HTTP
// clients that present a chosen identity — or a forged one — and a process
// harness that starts a real service binary with its certificate.
//
// The tests that use them are mtls_flow_test.go (the whole product over mutual
// TLS, and what each kind of attacker is refused) and mtls_lifecycle_test.go
// (certificate rotation on a live process, and refusals to start).
package integration_test

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// mtlsDomain is the trust domain of every PKI these tests mint. It is not the
// default one on purpose: a service that only works when the default is left
// in place would not be reading TLS_TRUST_DOMAIN at all.
const mtlsDomain = "it.openbastion"

// ---------------------------------------------------------------------
// PKI
// ---------------------------------------------------------------------

// testPKI is a certificate authority and the identities of a whole deployment,
// on disk where the services expect to find them.
type testPKI struct {
	dir string
	ca  *pki.CA
}

func newTestPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	ca, err := pki.InitDir(dir, mtlsDomain, 24*time.Hour)
	if err != nil {
		t.Fatalf("pki init: %v", err)
	}
	for _, service := range pki.StandardServices {
		if _, err := pki.IssueToDir(ca, dir, service, pki.IssueOptions{TTL: time.Hour}); err != nil {
			t.Fatalf("pki issue %s: %v", service, err)
		}
	}
	return &testPKI{dir: dir, ca: ca}
}

// env is the environment that gives a process the identity of service.
func (p *testPKI) env(service string, extra ...string) []string {
	return append([]string{
		"INTERNAL_TLS=required",
		"TLS_TRUST_DOMAIN=" + mtlsDomain,
		"TLS_CERT_FILE=" + pki.CertFile(p.dir, service),
		"TLS_KEY_FILE=" + pki.KeyFile(p.dir, service),
		"TLS_CA_FILE=" + pki.CAFile(p.dir),
	}, extra...)
}

func (p *testPKI) roots() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(p.ca.Cert)
	return pool
}

// clientAs is an HTTP client holding the real certificate of service — what the
// service itself would use, or what an attacker who stole its key would.
func (p *testPKI) clientAs(t *testing.T, service string) *http.Client {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(pki.CertFile(p.dir, service), pki.KeyFile(p.dir, service))
	if err != nil {
		t.Fatalf("loading the identity of %s: %v", service, err)
	}
	return newMTLSClient(p.roots(), &cert)
}

// clientWith is a client presenting leaf, trusting roots to verify the server.
func clientWith(t *testing.T, roots *x509.CertPool, leaf *pki.Leaf) *http.Client {
	t.Helper()
	cert, err := tls.X509KeyPair(leaf.CertPEM, leaf.KeyPEM)
	if err != nil {
		t.Fatalf("forged identity: %v", err)
	}
	return newMTLSClient(roots, &cert)
}

// newMTLSClient never reuses a connection: every request is a fresh handshake,
// so what a test observes is what the server decides now, not what it decided
// for a connection opened earlier.
func newMTLSClient(roots *x509.CertPool, cert *tls.Certificate) *http.Client {
	cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, NextProtos: []string{"http/1.1"}}
	if cert != nil {
		cfg.Certificates = []tls.Certificate{*cert}
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: cfg, DisableKeepAlives: true},
		Timeout:   10 * time.Second,
	}
}

// ---------------------------------------------------------------------
// Requests
// ---------------------------------------------------------------------

// call sends one request and returns whatever came back — including the error,
// because for the attacker tests a refused handshake is the expected answer.
func call(c *http.Client, method, url string, body any) (status int, raw string, err error) {
	var rd io.Reader
	if body != nil {
		encoded, merr := json.Marshal(body)
		if merr != nil {
			return 0, "", merr
		}
		rd = bytes.NewReader(encoded)
	}
	req, err := http.NewRequest(method, url, rd)
	if err != nil {
		return 0, "", err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), nil
}

// mustCall is call for requests that are expected to get an answer.
func mustCall(t *testing.T, c *http.Client, method, url string, body any) (int, string) {
	t.Helper()
	status, raw, err := call(c, method, url, body)
	if err != nil {
		t.Fatalf("%s %s: %v", method, url, err)
	}
	return status, raw
}

func mtlsCreateUser(t *testing.T, c *http.Client, authnURL, username, password string, roles []string) {
	t.Helper()
	status, raw := mustCall(t, c, http.MethodPost, authnURL+"/auth/v1/users", map[string]any{
		"username": username, "displayName": username, "password": password, "roles": roles,
	})
	if status != http.StatusCreated {
		t.Fatalf("create user %s: status %d: %s", username, status, raw)
	}
}

// guardRefusal is the body of a refusal by the caller rules (mtls.Guard), as
// opposed to a refusal by a service's own authorization: it tells a request
// stopped at the door from one that got in and was told no.
const guardRefusal = "forbidden\n"

// ---------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------

// syncBuffer is a buffer a process writes while the test reads it.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// mtlsProc is a running service with its output kept, because under mutual TLS
// the log is part of what is being tested (what was refused, and why).
type mtlsProc struct {
	*runningService
	out *syncBuffer
}

func (m *mtlsProc) alive() bool { return m.cmd.Process.Signal(syscall.Signal(0)) == nil }

// startMTLSService starts bin as service, listening on port, with its
// certificate from p and the given environment. It returns once the service
// answers /healthz over mutual TLS.
func startMTLSService(t *testing.T, root, bin, port string, p *testPKI, service string, extraEnv ...string) *mtlsProc {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append(append(buildEnv(root), "PORT="+port), p.env(service, extraEnv...)...)
	out := &syncBuffer{}
	cmd.Stdout, cmd.Stderr = out, out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", bin, err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})

	baseURL := "https://127.0.0.1:" + port
	probe := p.clientAs(t, mtls.AdminCLI)
	deadline := time.Now().Add(10 * time.Second)
	var last error
	for time.Now().Before(deadline) {
		status, _, err := call(probe, http.MethodGet, baseURL+"/healthz", nil)
		if err == nil && status == http.StatusOK {
			return &mtlsProc{runningService: &runningService{baseURL: baseURL, cmd: cmd}, out: out}
		}
		if err == nil {
			err = fmt.Errorf("status %d", status)
		}
		last = err
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("%s at %s did not become healthy over mutual TLS: %v\noutput so far:\n%s", service, baseURL, last, out.String())
	return nil
}

// waitUntil polls cond until it holds, failing the test with what if it never does.
func waitUntil(t *testing.T, limit time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("gave up waiting for %s", what)
}

// servedSerial is the serial number of the certificate the server at url
// presents to a fresh connection.
func servedSerial(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, url+"/healthz", nil)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("GET %s/healthz: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		t.Fatalf("GET %s/healthz: no TLS peer certificate", url)
	}
	return resp.TLS.PeerCertificates[0].SerialNumber.String()
}

// jsonField reads one string field of a JSON object.
func jsonField(t *testing.T, raw, field string) string {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		t.Fatalf("decoding %q: %v", raw, err)
	}
	s, _ := m[field].(string)
	return s
}

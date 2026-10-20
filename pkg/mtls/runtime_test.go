package mtls_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

func TestSetup_ARequiredServiceMustHoldItsOwnCertificate(t *testing.T) {
	e := newEnv(t)
	s := e.issue("session-broker", pki.IssueOptions{})

	if _, err := mtls.SetupWith("password-vault", s); err == nil {
		t.Fatal("the Vault started with the broker's certificate")
	} else if !strings.Contains(err.Error(), `"session-broker"`) || !strings.Contains(err.Error(), `"password-vault"`) {
		t.Errorf("the error should name both identities: %v", err)
	}

	rt, err := mtls.SetupWith("session-broker", s)
	if err != nil {
		t.Fatal(err)
	}
	if !rt.Enabled() || rt.Credentials() == nil || rt.Credentials().Identity() != "session-broker" {
		t.Errorf("enabled=%v", rt.Enabled())
	}
	if got := rt.DefaultURL("127.0.0.1:8081"); got != "https://127.0.0.1:8081" {
		t.Errorf("default URL %q", got)
	}
}

func TestSetup_RefusesWhatItCannotUse(t *testing.T) {
	e := newEnv(t)
	s := e.issue("session-broker", pki.IssueOptions{})
	s.CertFile += ".missing"
	if _, err := mtls.SetupWith("session-broker", s); err == nil {
		t.Fatal("started without a readable certificate")
	}
	if _, err := mtls.SetupWith("Not A Service", mtls.Settings{Mode: mtls.Disabled}); err == nil {
		t.Fatal("accepted an invalid service name")
	}
}

func TestSetup_FromTheEnvironment(t *testing.T) {
	e := newEnv(t)
	s := e.issue("audit-service", pki.IssueOptions{})
	t.Setenv("INTERNAL_TLS", "")
	t.Setenv("TLS_CERT_FILE", s.CertFile)
	t.Setenv("TLS_KEY_FILE", s.KeyFile)
	t.Setenv("TLS_CA_FILE", s.CAFile)
	t.Setenv("TLS_TRUST_DOMAIN", testDomain)
	rt, err := mtls.Setup("audit-service")
	if err != nil || !rt.Enabled() {
		t.Fatalf("%v", err)
	}

	t.Setenv("TLS_CERT_FILE", "")
	if _, err := mtls.Setup("audit-service"); err == nil || !strings.Contains(err.Error(), "refusing to start") {
		t.Fatalf("a Required service without a certificate must not start: %v", err)
	}
}

func TestRuntime_DisabledIsPlainAndSaysSo(t *testing.T) {
	rt, err := mtls.SetupWith("password-vault", mtls.Settings{Mode: mtls.Disabled})
	if err != nil {
		t.Fatal(err)
	}
	if rt.Enabled() || rt.Credentials() != nil {
		t.Fatal("a disabled runtime has credentials")
	}
	if got := rt.DefaultURL("127.0.0.1:8081"); got != "http://127.0.0.1:8081" {
		t.Errorf("default URL %q", got)
	}
	c, err := rt.Client(mtls.Peer{URL: "http://127.0.0.1:8081", Service: "password-vault"})
	if err != nil || c != http.DefaultClient {
		t.Errorf("client %v, %v", c, err)
	}
	// no identity exists, so there is nothing to guard: the handler is untouched
	called := false
	h := rt.Handler(vaultRules, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	h.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest("GET", "/anything", nil))
	if !called {
		t.Error("the disabled runtime guarded a route")
	}
	if srv := rt.Server(":0", h, nil); srv.TLSConfig != nil {
		t.Error("the disabled runtime serves TLS")
	}
}

func TestRuntime_RequiredGuardsAndServesTLS(t *testing.T) {
	e := newEnv(t)
	rt, err := mtls.SetupWith("password-vault", e.issue("password-vault", pki.IssueOptions{}))
	if err != nil {
		t.Fatal(err)
	}
	called := false
	h := rt.Handler(vaultRules, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true }))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/healthz", nil)) // no TLS state: an unauthenticated request
	if rec.Code != http.StatusUnauthorized || called {
		t.Errorf("an unauthenticated request got %d, handler ran: %v", rec.Code, called)
	}

	srv := rt.Server(":0", h, vaultRules)
	if srv.TLSConfig == nil || srv.ReadHeaderTimeout <= 0 || srv.IdleTimeout <= 0 {
		t.Errorf("the server is not hardened: %+v", srv)
	}
}

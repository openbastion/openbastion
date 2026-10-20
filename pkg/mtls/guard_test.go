package mtls_test

import (
	"bufio"
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// vaultRules is the shape of a real service's table: who may call which route.
var vaultRules = []mtls.Rule{
	{Method: "POST", Path: "/vault/v1/authorize-scope", Callers: []string{"session-broker"}},
	{Method: "POST", Path: "/vault/v1/fetch-credential", Callers: []string{"ssh-proxy"}},
	{Method: "GET", Path: "/vault/v1/accounts/", Prefix: true, Callers: []string{"api-gateway", "session-broker"}},
	{Method: "DELETE", Path: "/vault/v1/accounts/", Prefix: true, Callers: []string{"api-gateway"}},
	{Path: "/healthz", Callers: []string{mtls.Any}},
}

func TestGuard_EachRouteAdmitsOnlyItsCallers(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), vaultRules)

	clientAs := func(service string) *http.Client {
		c, err := e.creds(service).Client(mtls.Peer{URL: srv.URL, Service: "password-vault"})
		must(t, err)
		return c
	}

	type call struct {
		caller, method, path string
		want                 int
	}
	for _, c := range []call{
		// the broker authorizes scopes; nobody else does
		{"session-broker", "POST", "/vault/v1/authorize-scope", 200},
		{"ssh-proxy", "POST", "/vault/v1/authorize-scope", 403},
		{"api-gateway", "POST", "/vault/v1/authorize-scope", 403},
		{"command-recorder", "POST", "/vault/v1/authorize-scope", 403},
		// the proxy redeems them; the broker — who holds scope tokens — must not
		{"ssh-proxy", "POST", "/vault/v1/fetch-credential", 200},
		{"session-broker", "POST", "/vault/v1/fetch-credential", 403},
		{"api-gateway", "POST", "/vault/v1/fetch-credential", 403},
		{"admin-cli", "POST", "/vault/v1/fetch-credential", 403},
		// the method is part of the rule
		{"session-broker", "GET", "/vault/v1/authorize-scope", 403},
		{"session-broker", "GET", "/vault/v1/accounts/acc_1", 200},
		{"session-broker", "DELETE", "/vault/v1/accounts/acc_1", 403},
		{"api-gateway", "DELETE", "/vault/v1/accounts/acc_1", 200},
		{"ssh-proxy", "GET", "/vault/v1/accounts/acc_1", 403},
		// a prefix is a subtree, not a string prefix
		{"api-gateway", "GET", "/vault/v1/accounts", 403},
		{"api-gateway", "GET", "/vault/v1/accounts-evil/x", 403},
		{"api-gateway", "GET", "/vault/v1/accountsX/", 403},
		// default deny: a route nobody wrote a rule for is unreachable
		{"api-gateway", "GET", "/nothing", 403},
		{"session-broker", "POST", "/vault/v1/onboard-account", 403},
		{"api-gateway", "GET", "/healthz/", 403},
		// "any authenticated service" is for health endpoints
		{"command-recorder", "GET", "/healthz", 200},
		{"admin-cli", "GET", "/healthz", 200},
	} {
		status, _, err := do(clientAs(c.caller), c.method, srv.URL+c.path)
		if err != nil || status != c.want {
			t.Errorf("%s %s %s: got %d (%v), want %d", c.caller, c.method, c.path, status, err, c.want)
		}
	}

	// the handlers ran for exactly the admitted calls, as the right callers
	for _, hit := range srv.served() {
		switch hit {
		case "session-broker POST /vault/v1/authorize-scope", "ssh-proxy POST /vault/v1/fetch-credential",
			"session-broker GET /vault/v1/accounts/acc_1", "api-gateway DELETE /vault/v1/accounts/acc_1",
			"command-recorder GET /healthz", "admin-cli GET /healthz":
		default:
			t.Errorf("a handler ran for %q", hit)
		}
	}
}

// rawStatus sends a hand-written request line — what a client library would
// never produce — over a real mutual-TLS connection.
func rawStatus(t *testing.T, e *env, srv *server, as string, requestLine string) int {
	t.Helper()
	conn, err := tls.Dial("tcp", srv.Addr, &tls.Config{
		RootCAs: e.pool(), MinVersion: tls.VersionTLS13,
		Certificates: []tls.Certificate{e.certFor(as, pki.IssueOptions{})},
	})
	must(t, err)
	defer conn.Close()
	if _, err := conn.Write([]byte(requestLine + " HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func TestGuard_ARequestCannotSlipPastARuleByHowItWritesItsPath(t *testing.T) {
	e := newEnv(t)
	srv := e.serve(e.creds("password-vault"), vaultRules)

	// The gateway may GET anything under /vault/v1/accounts/ — but not authorize
	// scopes. Every one of these tries to reach authorize-scope through that rule.
	for _, target := range []string{
		"POST /vault/v1/accounts/../authorize-scope",
		"POST /vault/v1/accounts/%2e%2e/authorize-scope",
		"POST /vault/v1/accounts/a%2F..%2Fauthorize-scope",
		"POST //vault/v1/authorize-scope",
		"POST /vault/v1/./authorize-scope",
		"POST /vault/v1/accounts/x/../../authorize-scope",
	} {
		if got := rawStatus(t, e, srv, "api-gateway", target); got == http.StatusOK {
			t.Errorf("%s: reached a handler", target)
		} else if got != http.StatusBadRequest {
			t.Errorf("%s: status %d, want 400", target, got)
		}
	}
	// A standard escape (%20) round-trips through the URL parser, so the guard
	// and the mux read the very same decoded path: not a way around a rule, and
	// served normally. Only escapes that change the path's structure (%2e, %2F)
	// leave a RawPath behind, and those are refused above.
	if got := rawStatus(t, e, srv, "api-gateway", "GET /vault/v1/accounts/a%20b"); got != http.StatusOK {
		t.Errorf("a standard escape: status %d, want 200", got)
	}
	// the control: the same connection style with a plain path is served
	if got := rawStatus(t, e, srv, "api-gateway", "GET /vault/v1/accounts/acc_1"); got != http.StatusOK {
		t.Errorf("the control: status %d", got)
	}
	for _, hit := range srv.served() {
		if hit != "api-gateway GET /vault/v1/accounts/acc_1" && hit != "api-gateway GET /vault/v1/accounts/a b" {
			t.Errorf("a handler ran for %q", hit)
		}
	}
}

func TestGuard_DoesNotTrustAConnectionThatWasNotAuthenticated(t *testing.T) {
	e := newEnv(t)
	pair := e.certFor("ssh-proxy", pki.IssueOptions{})
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	must(t, err)
	foreign := e.forge("spiffe://elsewhere.test/ssh-proxy")
	foreignLeaf, err := x509.ParseCertificate(foreign.Certificate[0])
	must(t, err)

	ran := 0
	h := mtls.Guard(testDomain, open, http.HandlerFunc(func(http.ResponseWriter, *http.Request) { ran++ }))
	status := func(state *tls.ConnectionState) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/", nil)
		req.TLS = state
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	for name, state := range map[string]*tls.ConnectionState{
		"no TLS at all":                            nil,
		"TLS, nothing presented":                   {},
		"a certificate that was never verified":    {PeerCertificates: []*x509.Certificate{leaf}},
		"a verified chain but no peer certificate": {VerifiedChains: [][]*x509.Certificate{{leaf}}},
	} {
		if got := status(state); got != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, got)
		}
	}
	if ran != 0 {
		t.Fatalf("the handler ran %d times for unauthenticated requests", ran)
	}

	// authenticated, but not as a member of this deployment
	if got := status(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{foreignLeaf}, VerifiedChains: [][]*x509.Certificate{{foreignLeaf}}}); got != http.StatusForbidden {
		t.Errorf("a certificate of another trust domain: status %d, want 403", got)
	}
	// the control: a verified identity of this deployment passes
	if got := status(&tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}, VerifiedChains: [][]*x509.Certificate{{leaf}}}); got != http.StatusOK || ran != 1 {
		t.Errorf("the control: status %d, ran %d", got, ran)
	}
}

func TestGuard_RefusesAMalformedRuleTableAtStartUp(t *testing.T) {
	next := http.NotFoundHandler()
	for name, rules := range map[string][]mtls.Rule{
		"a relative path":          {{Path: "x", Callers: []string{"a"}}},
		"no callers":               {{Path: "/x"}},
		"a prefix without a slash": {{Path: "/x", Prefix: true, Callers: []string{"a"}}},
		"an invalid caller":        {{Path: "/x", Callers: []string{"Not A Service"}}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s: accepted", name)
				}
			}()
			mtls.Guard(testDomain, rules, next)
		}()
	}
}

func TestCallerFrom(t *testing.T) {
	if _, ok := mtls.CallerFrom(httptest.NewRequest("GET", "/", nil).Context()); ok {
		t.Error("a caller appeared from nowhere")
	}
	ctx := mtls.WithCaller(httptest.NewRequest("GET", "/", nil).Context(), "ssh-proxy")
	if who, ok := mtls.CallerFrom(ctx); !ok || who != "ssh-proxy" {
		t.Errorf("%q %v", who, ok)
	}
	if _, ok := mtls.CallerFrom(mtls.WithCaller(ctx, "")); ok {
		t.Error("an empty caller counts as an identity")
	}
}

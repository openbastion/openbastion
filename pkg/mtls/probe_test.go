package mtls_test

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
)

// probeTarget serves status on path under the identity of service, and returns its port.
func probeTarget(t *testing.T, e *env, service, path string, status int) int {
	t.Helper()
	creds, err := mtls.NewCredentials(e.issue(service, pki.IssueOptions{}))
	must(t, err)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
	}))
	srv.TLS = creds.ServerTLS()
	srv.StartTLS()
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	return p
}

// probeAs puts the identity of service in the environment, as the container does.
func probeAs(t *testing.T, e *env, service string) {
	t.Helper()
	s := e.settingsFor(service)
	t.Setenv("INTERNAL_TLS", "")
	t.Setenv("TLS_CERT_FILE", s.CertFile)
	t.Setenv("TLS_KEY_FILE", s.KeyFile)
	t.Setenv("TLS_CA_FILE", s.CAFile)
	t.Setenv("TLS_TRUST_DOMAIN", testDomain)
}

// The healthcheck of an image with no shell (ADR-0072): the running service, asked on the loopback
// under its own identity; a 200 is up, anything else is not, and so is another service in its place.
func TestProbeSelf(t *testing.T) {
	e := newEnv(t)
	up := probeTarget(t, e, "video-recorder", "/readyz", http.StatusOK)
	down := probeTarget(t, e, "video-recorder", "/readyz", http.StatusServiceUnavailable)
	impostor := probeTarget(t, e, "audit-service", "/readyz", http.StatusOK)
	probeAs(t, e, "video-recorder")
	ctx := context.Background()
	if err := mtls.ProbeSelf(ctx, "video-recorder", up, "/readyz"); err != nil {
		t.Fatalf("a service that answers 200: %v", err)
	}
	for name, c := range map[string]struct {
		port int
		path string
	}{
		"a service that answers 503":        {down, "/readyz"},
		"another service in its place":      {impostor, "/readyz"},
		"a path the service does not serve": {up, "/nowhere"},
		"no port":                           {0, "/readyz"},
		"a path that is not one":            {up, "readyz"},
		"a query smuggled in the path":      {up, "/readyz?x=1"},
	} {
		if err := mtls.ProbeSelf(ctx, "video-recorder", c.port, c.path); err == nil {
			t.Errorf("%s: probed as up", name)
		}
	}
}

// Without mutual TLS (development), the probe speaks plain HTTP, as the service does.
func TestProbeSelf_WithoutMutualTLS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(srv.Close)
	_, port, _ := net.SplitHostPort(srv.Listener.Addr().String())
	p, _ := strconv.Atoi(port)
	t.Setenv("INTERNAL_TLS", "disabled")
	if err := mtls.ProbeSelf(context.Background(), "rdp-vnc-proxy", p, "/healthz"); err != nil {
		t.Fatal(err)
	}
}

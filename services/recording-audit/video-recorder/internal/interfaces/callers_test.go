package interfaces

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestHTTPCallerRules(t *testing.T) {
	mtlstest.Check(t, HTTPCallerRules(), []mtlstest.Case{
		mtlstest.Allow("rdp-proxy", "GET", "/readyz"),
		mtlstest.Allow("api-gateway", "GET", "/readyz"),
		mtlstest.Deny("rdp-proxy", "POST", "/readyz"),
		mtlstest.Allow("api-gateway", "GET", "/healthz"),
		mtlstest.Deny("api-gateway", "POST", "/healthz"),
		mtlstest.Deny("admin-cli", "GET", "/recordings/s1"),
	})
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), HTTPCallerRules(), []mtlstest.Route{
		{Method: http.MethodGet, Path: "/healthz"},
		{Method: http.MethodGet, Path: "/readyz"},
	})
}

func TestHealthEndpointsRejectNonGETMethods(t *testing.T) {
	server := NewHTTPServer(nil)
	for _, path := range []string{"/healthz", "/readyz"} {
		request := httptest.NewRequest(http.MethodPost, path, nil)
		response := httptest.NewRecorder()
		server.Routes().ServeHTTP(response, request)
		if response.Code != http.StatusMethodNotAllowed {
			t.Errorf("POST %s = %d, want %d", path, response.Code, http.StatusMethodNotAllowed)
		}
	}
}

func TestGRPCCallerRulesAreRestrictedToRDPProxyAndGateway(t *testing.T) {
	want := map[string][]string{
		"/openbastion.recording.v1.VideoRecording/StreamVideoSegments": {mtls.RDPVNCProxy},
		"/openbastion.recording.v1.VideoRecording/GetVideoSegment":     {mtls.APIGateway},
		"/openbastion.recording.v1.VideoRecording/CheckReadiness":      {mtls.RDPVNCProxy},
	}
	got := make(map[string][]string)
	for _, rule := range GRPCCallerRules() {
		got[rule.Method] = rule.Callers
	}
	if len(got) != len(want) {
		t.Fatalf("got %d RPC rules, want %d", len(got), len(want))
	}
	for method, callers := range want {
		actual, exists := got[method]
		if !exists || len(actual) != len(callers) || actual[0] != callers[0] {
			t.Errorf("%s callers = %v, want %v", method, actual, callers)
		}
	}
}

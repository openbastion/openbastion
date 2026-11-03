package interfaces

import (
	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
	"testing"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("session-broker", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/establish-session"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/revoke-session"),
		mtlstest.Allow("api-gateway", "GET", "/internal/v1/screen"),
		mtlstest.Deny("session-broker", "GET", "/internal/v1/screen"),
		mtlstest.Deny("admin-cli", "GET", "/internal/v1/screen"),
		mtlstest.Allow("session-broker", "GET", "/healthz"),
	})
}
func TestEveryRegisteredRouteHasCallerRule(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil, nil, nil, nil, "", nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/internal/v1/establish-session"},
		{Method: "POST", Path: "/internal/v1/revoke-session"},
		{Method: "GET", Path: "/internal/v1/screen"},
		{Method: "GET", Path: "/healthz"},
	})
}

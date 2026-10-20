package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("session-broker", "POST", "/internal/v1/establish-session"),
		// none of these may open a session, and so none may ask for break-glass
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("command-recorder", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("admin-cli", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("ssh-proxy", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("session-broker", "GET", "/internal/v1/establish-session"),
		mtlstest.Allow("session-broker", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil, "").Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/internal/v1/establish-session"}, {Method: "GET", Path: "/healthz"},
	})
}

package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("api-gateway", "POST", "/sessions"),
		mtlstest.Allow("api-gateway", "GET", "/sessions/s1"),
		mtlstest.Allow("api-gateway", "DELETE", "/sessions/s1"),
		mtlstest.Allow("api-gateway", "POST", "/sessions/s1/connect"),
		// a forged requestedBy/actorRoles or break-glass request from any other service
		mtlstest.Deny("ssh-proxy", "POST", "/sessions"),
		mtlstest.Deny("password-vault", "POST", "/sessions"),
		mtlstest.Deny("command-recorder", "POST", "/sessions/s1/connect"),
		mtlstest.Deny("admin-cli", "POST", "/sessions"),
		mtlstest.Deny("session-broker", "POST", "/sessions"),
		mtlstest.Allow("ssh-proxy", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/sessions"}, {Method: "GET", Path: "/sessions/s1"},
		{Method: "POST", Path: "/sessions/s1/connect"}, {Method: "GET", Path: "/healthz"},
	})
}

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
		mtlstest.Allow("api-gateway", "POST", "/sessions/s1/approve"),
		mtlstest.Allow("api-gateway", "POST", "/sessions/s1/reject"),
		// a decision on a break-glass request (ADR-0011): the Gateway states who decides,
		// so nobody else may — whatever identity they hold
		mtlstest.Deny("password-vault", "POST", "/sessions/s1/approve"),
		mtlstest.Deny("ssh-proxy", "POST", "/sessions/s1/approve"),
		mtlstest.Deny("authentication", "POST", "/sessions/s1/approve"),
		mtlstest.Deny("authorization", "POST", "/sessions/s1/reject"),
		mtlstest.Deny("command-recorder", "POST", "/sessions/s1/reject"),
		mtlstest.Deny("admin-cli", "POST", "/sessions/s1/approve"),
		mtlstest.Deny("session-broker", "POST", "/sessions/s1/approve"),
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
		{Method: "POST", Path: "/sessions/s1/connect"}, {Method: "POST", Path: "/sessions/s1/approve"},
		{Method: "POST", Path: "/sessions/s1/reject"}, {Method: "GET", Path: "/healthz"},
	})
}

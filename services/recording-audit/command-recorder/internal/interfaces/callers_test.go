package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("ssh-proxy", "POST", "/recorder/v1/command-entries"),
		// a forged entry in a replay: nobody but the proxy that ran the session
		mtlstest.Deny("session-broker", "POST", "/recorder/v1/command-entries"),
		mtlstest.Deny("api-gateway", "POST", "/recorder/v1/command-entries"),
		mtlstest.Deny("password-vault", "POST", "/recorder/v1/command-entries"),
		mtlstest.Deny("admin-cli", "POST", "/recorder/v1/command-entries"),

		mtlstest.Allow("api-gateway", "GET", "/recorder/v1/sessions/s1/commands"),
		mtlstest.Deny("ssh-proxy", "GET", "/recorder/v1/sessions/s1/commands"),
		mtlstest.Deny("session-broker", "GET", "/recorder/v1/sessions/s1/commands"),
		mtlstest.Deny("admin-cli", "GET", "/recorder/v1/sessions/s1/commands"),
		mtlstest.Deny("api-gateway", "POST", "/recorder/v1/sessions/s1/commands"),

		mtlstest.Allow("ssh-proxy", "GET", "/readyz"),
		mtlstest.Allow("api-gateway", "GET", "/readyz"),
		mtlstest.Deny("ssh-proxy", "POST", "/readyz"),
		mtlstest.Allow("session-broker", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/recorder/v1/command-entries"},
		{Method: "GET", Path: "/recorder/v1/sessions/s1/commands"},
		{Method: "GET", Path: "/readyz"}, {Method: "GET", Path: "/healthz"},
	})
}

package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("api-gateway", "POST", "/authz/v1/policies"),
		// a forged admin claim from anyone else never reaches the handler
		mtlstest.Deny("session-broker", "POST", "/authz/v1/policies"),
		mtlstest.Deny("ssh-proxy", "POST", "/authz/v1/policies"),
		mtlstest.Deny("command-recorder", "POST", "/authz/v1/policies"),
		mtlstest.Deny("admin-cli", "POST", "/authz/v1/policies"),

		mtlstest.Allow("session-broker", "POST", "/authz/v1/check-access"),
		mtlstest.Allow("password-vault", "POST", "/authz/v1/check-access"),
		mtlstest.Allow("command-recorder", "POST", "/authz/v1/check-access"),
		mtlstest.Allow("video-recorder", "POST", "/authz/v1/check-access"),
		mtlstest.Deny("rdp-vnc-proxy", "POST", "/authz/v1/check-access"),
		mtlstest.Deny("ssh-proxy", "POST", "/authz/v1/check-access"),
		mtlstest.Deny("api-gateway", "POST", "/authz/v1/check-access"),
		mtlstest.Deny("session-broker", "GET", "/authz/v1/check-access"),

		mtlstest.Allow("ssh-proxy", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/authz/v1/policies"}, {Method: "POST", Path: "/authz/v1/check-access"}, {Method: "GET", Path: "/healthz"},
	})
}

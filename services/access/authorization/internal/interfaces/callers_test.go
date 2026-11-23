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

		// ADR-0131: only the Gateway asks the Admin UI's capabilities.
		mtlstest.Allow("api-gateway", "POST", "/authz/v1/capabilities"),
		mtlstest.Deny("session-broker", "POST", "/authz/v1/capabilities"),
		mtlstest.Deny("password-vault", "POST", "/authz/v1/capabilities"),
		mtlstest.Deny("admin-cli", "POST", "/authz/v1/capabilities"),
		mtlstest.Deny("api-gateway", "GET", "/authz/v1/capabilities"),

		mtlstest.Allow("ssh-proxy", "GET", "/healthz"),
		mtlstest.Allow("admin-cli", "GET", "/metrics"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "GET", Path: "/metrics"},
		{Method: "POST", Path: "/authz/v1/policies"}, {Method: "POST", Path: "/authz/v1/check-access"}, {Method: "POST", Path: "/authz/v1/capabilities"}, {Method: "GET", Path: "/healthz"},
	})
}

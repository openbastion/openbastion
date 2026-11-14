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
		// Cutting a session is the Broker's decision alone (ADR-0018): none of these may
		// end somebody's session, and the Broker's own route does not answer a GET.
		mtlstest.Allow("session-broker", "POST", "/internal/v1/revoke-session"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/inject-vault-secret"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/inject-vault-secret"),
		mtlstest.Deny("command-recorder", "POST", "/internal/v1/inject-vault-secret"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/inject-vault-secret"),
		mtlstest.Deny("ssh-proxy", "POST", "/internal/v1/inject-vault-secret"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("command-recorder", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("authorization", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("admin-cli", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("ssh-proxy", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("session-broker", "GET", "/internal/v1/revoke-session"),
		mtlstest.Deny("session-broker", "DELETE", "/internal/v1/revoke-session"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil, "").Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/internal/v1/establish-session"}, {Method: "POST", Path: "/internal/v1/revoke-session"},
		{Method: "POST", Path: "/internal/v1/inject-vault-secret"},
		{Method: "GET", Path: "/healthz"},
	})
}

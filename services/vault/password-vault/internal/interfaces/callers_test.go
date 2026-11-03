package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		// ADR-0003, as a table: whoever authorizes a scope cannot redeem it...
		mtlstest.Allow("session-broker", "POST", "/vault/v1/authorize-scope"),
		mtlstest.Deny("session-broker", "POST", "/vault/v1/fetch-credential"),
		// ...and whoever redeems it cannot authorize one.
		mtlstest.Allow("ssh-proxy", "POST", "/vault/v1/fetch-credential"),
		mtlstest.Allow("rdp-vnc-proxy", "POST", "/vault/v1/fetch-credential"),
		mtlstest.Deny("rdp-vnc-proxy", "POST", "/vault/v1/authorize-scope"),
		mtlstest.Deny("ssh-proxy", "POST", "/vault/v1/authorize-scope"),
		// the Gateway, the control plane's front door, is neither
		mtlstest.Deny("api-gateway", "POST", "/vault/v1/fetch-credential"),
		mtlstest.Deny("api-gateway", "POST", "/vault/v1/authorize-scope"),
		mtlstest.Deny("admin-cli", "POST", "/vault/v1/fetch-credential"),
		mtlstest.Deny("command-recorder", "POST", "/vault/v1/fetch-credential"),
		mtlstest.Deny("rdp-vnc-proxy", "POST", "/vault/v1/authorize-scope"),

		mtlstest.Allow("api-gateway", "POST", "/vault/v1/onboard-account"),
		mtlstest.Allow("api-gateway", "POST", "/vault/v1/rotate"),
		mtlstest.Allow("api-gateway", "GET", "/vault/v1/accounts"),
		mtlstest.Allow("api-gateway", "GET", "/vault/v1/accounts/acc_1"),
		mtlstest.Allow("api-gateway", "DELETE", "/vault/v1/accounts/acc_1"),
		mtlstest.Deny("session-broker", "POST", "/vault/v1/onboard-account"),
		mtlstest.Deny("session-broker", "POST", "/vault/v1/rotate"),
		mtlstest.Deny("ssh-proxy", "POST", "/vault/v1/onboard-account"),
		mtlstest.Deny("ssh-proxy", "GET", "/vault/v1/accounts"),

		// the Broker may read an account's metadata, never change or list them
		mtlstest.Allow("session-broker", "GET", "/vault/v1/accounts/acc_1"),
		mtlstest.Deny("session-broker", "DELETE", "/vault/v1/accounts/acc_1"),
		mtlstest.Deny("session-broker", "GET", "/vault/v1/accounts"),
		mtlstest.Deny("ssh-proxy", "GET", "/vault/v1/accounts/acc_1"),

		mtlstest.Allow("command-recorder", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/vault/v1/authorize-scope"}, {Method: "POST", Path: "/vault/v1/fetch-credential"},
		{Method: "POST", Path: "/vault/v1/onboard-account"}, {Method: "POST", Path: "/vault/v1/rotate"},
		{Method: "GET", Path: "/vault/v1/accounts"}, {Method: "GET", Path: "/vault/v1/accounts/acc_1"},
		{Method: "DELETE", Path: "/vault/v1/accounts/acc_1"}, {Method: "GET", Path: "/healthz"},
	})
}

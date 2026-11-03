package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Password Vault
// (ADR-0010). A route not listed here is refused to everyone.
//
// The two halves of ADR-0003 are separate callers: the Session Broker authorizes
// a scope and may never redeem it; each protocol proxy redeems only its own scope.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodPost, Path: "/vault/v1/authorize-scope", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/vault/v1/fetch-credential", Callers: []string{mtls.SSHProxy, mtls.RDPVNCProxy}},

		// Administration of accounts goes through the Gateway, on behalf of an
		// authenticated user whose roles the Vault then checks with Authorization.
		{Method: http.MethodPost, Path: "/vault/v1/onboard-account", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/vault/v1/rotate", Callers: []string{mtls.APIGateway}},
		// A session ended: the Broker asks for a rotation after use (ADR-0037).
		{Method: http.MethodPost, Path: "/vault/v1/rotate-after-use", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/vault/v1/accounts", Callers: []string{mtls.APIGateway}},
		// Account metadata: the Broker resolves where and as whom to connect.
		{Method: http.MethodGet, Path: "/vault/v1/accounts/", Prefix: true, Callers: []string{mtls.APIGateway, mtls.SessionBroker}},
		{Method: http.MethodDelete, Path: "/vault/v1/accounts/", Prefix: true, Callers: []string{mtls.APIGateway}},
		// Pinning a target's host key (ADR-0039): an administrator, through the Gateway.
		{Method: http.MethodPut, Path: "/vault/v1/accounts/", Prefix: true, Callers: []string{mtls.APIGateway}},

		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

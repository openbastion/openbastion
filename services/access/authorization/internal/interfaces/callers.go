package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Authorization
// Service (ADR-0010). A route not listed here is refused to everyone.
//
// Callers supply the roles they are asking about (check-access) or acting with
// (policies): the service trusts that claim only because only these services may
// make it. That is the point of the table — before mutual TLS, anyone who could
// reach this port could claim platform-admin.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		// Creating a policy is an administrative act, made on behalf of a user the
		// Gateway has authenticated.
		{Method: http.MethodPost, Path: "/authz/v1/policies", Callers: []string{mtls.APIGateway}},
		// Every service that enforces RBAC on its own routes asks here.
		{Method: http.MethodPost, Path: "/authz/v1/check-access",
			Callers: []string{mtls.SessionBroker, mtls.PasswordVault, mtls.CommandRecorder}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Authorization
// Service (ADR-0010). A route not listed here is refused to everyone.
//
// Callers supply the roles they are asking about (check-access) or acting with
// (policies). The Gateway's roles come from its verified end-user token; other
// workloads may ask only on behalf of identities they received through their
// authenticated internal contracts. The caller table prevents arbitrary network
// clients and unrelated workloads from claiming platform-admin.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		// Creating a policy is an administrative act, made on behalf of a user the
		// Gateway has authenticated.
		{Method: http.MethodPost, Path: "/authz/v1/policies", Callers: []string{mtls.APIGateway}},
		// Every service that enforces RBAC on its own routes asks here.
		{Method: http.MethodPost, Path: "/authz/v1/check-access",
			Callers: []string{mtls.APIGateway, mtls.SessionBroker, mtls.WorkflowService, mtls.PasswordVault, mtls.CommandRecorder, mtls.VideoRecorder}},
		// ADR-0131: the Admin UI's capabilities, asked by the Gateway for the caller it verified.
		{Method: http.MethodPost, Path: "/authz/v1/capabilities", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/metrics", Callers: []string{mtls.Any}}, // ADR-0135: pool telemetry
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the SSH Proxy's
// internal API (ADR-0010). A route not listed here is refused to everyone.
//
// Only the Session Broker establishes — and revokes — sessions. That matters beyond who may open
// a ticket: the request carries the break-glass flag (ADR-0009), and a caller
// that could set it could ask for a session without a recording.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodPost, Path: "/internal/v1/establish-session", Callers: []string{mtls.SessionBroker}},
		// Cutting a session is the Broker's decision alone (ADR-0018): a caller that
		// could revoke could end anybody's session, and one that could not be refused
		// by the route could keep a revoked one alive by never being told.
		{Method: http.MethodPost, Path: "/internal/v1/revoke-session", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/inject-vault-secret", Callers: []string{mtls.SessionBroker}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

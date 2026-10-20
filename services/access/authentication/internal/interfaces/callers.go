package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Authentication
// Service (ADR-0010). A route not listed here is refused to everyone.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		// The Gateway is the only door for users: it forwards the login and asks
		// whether a bearer token is valid.
		{Method: http.MethodPost, Path: "/auth/v1/login", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/verify", Callers: []string{mtls.APIGateway}},
		// Creating a local user has no public surface yet: it is operator tooling.
		{Method: http.MethodPost, Path: "/auth/v1/users", Callers: []string{mtls.AdminCLI}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

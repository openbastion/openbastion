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
		// Federated login (ADR-0035): the Gateway forwards both ends of it.
		{Method: http.MethodPost, Path: "/auth/v1/oidc/start", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/oidc/callback", Callers: []string{mtls.APIGateway}},
		// Directory login (ADR-0061): the Gateway forwards it, and asks whether it is on.
		{Method: http.MethodGet, Path: "/auth/v1/ldap", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/ldap/login", Callers: []string{mtls.APIGateway}},
		// The second factor (ADR-0062): the user's steps through the Gateway; the administrator's
		// gestures from the CLI only.
		{Method: http.MethodPost, Path: "/auth/v1/mfa/verify", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/mfa/enroll", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/mfa/enroll/confirm", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/auth/v1/mfa/enrollment-codes", Callers: []string{mtls.AdminCLI}},
		{Method: http.MethodPost, Path: "/auth/v1/mfa/reset", Callers: []string{mtls.AdminCLI}},
		// Creating a local user has no public surface yet: it is operator tooling.
		{Method: http.MethodPost, Path: "/auth/v1/users", Callers: []string{mtls.AdminCLI}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

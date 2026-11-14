package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/login"),
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/verify"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/users"),
		// the Gateway cannot mint users, and nobody but the Gateway can verify tokens
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/users"),
		mtlstest.Deny("session-broker", "POST", "/auth/v1/verify"),
		mtlstest.Allow("session-broker", "POST", "/auth/v1/internal/action-step-up/start"),
		mtlstest.Allow("session-broker", "POST", "/auth/v1/internal/action-step-up/verify"),
		mtlstest.Allow("session-broker", "POST", "/auth/v1/internal/action-step-up/consume"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/internal/action-step-up/consume"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/internal/action-step-up/start"),
		mtlstest.Deny("ssh-proxy", "POST", "/auth/v1/internal/action-step-up/verify"),
		mtlstest.Deny("ssh-proxy", "POST", "/auth/v1/login"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/login"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/verify"),
		mtlstest.Deny("api-gateway", "GET", "/auth/v1/verify"),
		mtlstest.Allow("password-vault", "GET", "/healthz"),
		// ADR-0061: directory login through the Gateway only.
		mtlstest.Allow("api-gateway", "GET", "/auth/v1/ldap"),
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/ldap/login"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/ldap/login"),
		mtlstest.Deny("session-broker", "POST", "/auth/v1/ldap/login"),
		// ADR-0062: the user's steps through the Gateway; the administrator's gestures from the CLI
		// only — the Gateway, which anyone reaches, can neither issue an enrollment code nor reset.
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/verify"),
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/enroll"),
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/enroll/confirm"),
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/webauthn/verify"), // ADR-0065
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/webauthn/enroll/confirm"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/mfa/webauthn/verify"),
		// ADR-0066: the user adds a key through the Gateway; only the CLI lists and revokes.
		mtlstest.Allow("api-gateway", "POST", "/auth/v1/mfa/webauthn/keys/add"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/keys"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/revoke-key"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/keys"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/revoke-key"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/reset"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/reset"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/mfa/verify"),
		mtlstest.Deny("session-broker", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Deny("api-gateway", "GET", "/auth/v1/mfa/enrollment-codes"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/auth/v1/users"},
		{Method: "POST", Path: "/auth/v1/login"},
		{Method: "POST", Path: "/auth/v1/verify"},
		{Method: "GET", Path: "/auth/v1/oidc"},
		{Method: "POST", Path: "/auth/v1/oidc/start"},
		{Method: "POST", Path: "/auth/v1/oidc/callback"},
		{Method: "GET", Path: "/auth/v1/ldap"},
		{Method: "POST", Path: "/auth/v1/ldap/login"},
		{Method: "POST", Path: "/auth/v1/mfa/verify"},
		{Method: "POST", Path: "/auth/v1/mfa/enroll"},
		{Method: "POST", Path: "/auth/v1/mfa/enroll/confirm"},
		{Method: "POST", Path: "/auth/v1/mfa/webauthn/verify"},
		{Method: "POST", Path: "/auth/v1/mfa/webauthn/enroll/confirm"},
		{Method: "POST", Path: "/auth/v1/mfa/webauthn/keys/add"},
		{Method: "POST", Path: "/auth/v1/mfa/keys"},
		{Method: "POST", Path: "/auth/v1/mfa/revoke-key"},
		{Method: "POST", Path: "/auth/v1/mfa/enrollment-codes"},
		{Method: "POST", Path: "/auth/v1/mfa/reset"},
		{Method: "POST", Path: "/auth/v1/internal/action-step-up/start"},
		{Method: "POST", Path: "/auth/v1/internal/action-step-up/verify"},
		{Method: "POST", Path: "/auth/v1/internal/action-step-up/consume"},
		{Method: "GET", Path: "/healthz"},
	})
}

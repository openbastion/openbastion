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
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Allow("admin-cli", "POST", "/auth/v1/mfa/reset"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Deny("api-gateway", "POST", "/auth/v1/mfa/reset"),
		mtlstest.Deny("admin-cli", "POST", "/auth/v1/mfa/verify"),
		mtlstest.Deny("session-broker", "POST", "/auth/v1/mfa/enrollment-codes"),
		mtlstest.Deny("api-gateway", "GET", "/auth/v1/mfa/enrollment-codes"),
	})
}

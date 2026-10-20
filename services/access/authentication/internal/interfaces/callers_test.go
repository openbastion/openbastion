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
	})
}

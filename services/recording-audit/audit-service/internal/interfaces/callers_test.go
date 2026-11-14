package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("session-broker", "POST", "/audit/v1/emit-event"),
		mtlstest.Allow("ssh-proxy", "POST", "/audit/v1/emit-event"),
		mtlstest.Allow("rdp-vnc-proxy", "POST", "/audit/v1/emit-event"),
		// a compromised service that is not an emitter cannot write the trail
		// The Vault writes its rotations since ADR-0037; Authorization still has nothing to write.
		mtlstest.Allow("password-vault", "POST", "/audit/v1/emit-event"),
		mtlstest.Allow("authentication", "POST", "/audit/v1/emit-event"), // ADR-0064: logins and second-factor gestures
		mtlstest.Deny("authentication", "GET", "/audit/v1/verify-chain"),
		mtlstest.Deny("authorization", "POST", "/audit/v1/emit-event"),
		// it writes the reads of a recording before it serves them (ADR-0022)
		mtlstest.Allow("command-recorder", "POST", "/audit/v1/emit-event"),
		// the Video Recorder audits every replay segment before serving it (ADR-0070)
		mtlstest.Allow("video-recorder", "POST", "/audit/v1/emit-event"),
		mtlstest.Deny("command-recorder", "GET", "/audit/v1/emit-event"),
		mtlstest.Deny("command-recorder", "GET", "/audit/v1/verify-chain"),
		mtlstest.Deny("api-gateway", "POST", "/audit/v1/emit-event"),
		mtlstest.Deny("admin-cli", "POST", "/audit/v1/emit-event"),
		mtlstest.Deny("agent", "POST", "/audit/v1/emit-event"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/emit-event"),

		mtlstest.Allow("admin-cli", "GET", "/audit/v1/verify-chain"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/verify-chain"),
		mtlstest.Deny("ssh-proxy", "GET", "/audit/v1/verify-chain"),
		mtlstest.Allow("command-recorder", "GET", "/healthz"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "POST", Path: "/audit/v1/emit-event"},
		{Method: "GET", Path: "/audit/v1/verify-chain"},
		{Method: "GET", Path: "/healthz"},
	})
}

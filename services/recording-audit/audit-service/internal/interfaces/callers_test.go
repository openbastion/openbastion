package interfaces

import (
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
)

func TestCallerRules(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("session-broker", "POST", "/audit/v1/emit-event"),
		mtlstest.Allow("workflow-service", "POST", "/audit/v1/emit-event"),
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
		// ADR-0119: the Gateway may read only the metadata projection, never verify the chain.
		mtlstest.Deny("api-gateway", "GET", "/audit/v1/verify-chain"),
		mtlstest.Allow("admin-cli", "GET", "/audit/v1/secret-injections"),
		mtlstest.Allow("api-gateway", "GET", "/audit/v1/secret-injections"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/secret-injections"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/verify-chain"),
		mtlstest.Deny("ssh-proxy", "GET", "/audit/v1/verify-chain"),
		mtlstest.Allow("command-recorder", "GET", "/healthz"),

		// ADR-0116 §4: the heads of the session metadata, the Session Broker's only.
		mtlstest.Allow("session-broker", "POST", "/audit/v1/session-metadata/attestations"),
		mtlstest.Allow("session-broker", "GET", "/audit/v1/session-metadata/head"),
		mtlstest.Allow("api-gateway", "GET", "/audit/v1/session-alerts"),
		mtlstest.Allow("api-gateway", "GET", "/audit/v1/session-alerts/summary"),
		mtlstest.Allow("api-gateway", "GET", "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef"),
		mtlstest.Allow("api-gateway", "POST", "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge"),
		mtlstest.Deny("admin-cli", "POST", "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge"),
		mtlstest.Deny("session-broker", "POST", "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge"),
		mtlstest.Deny("admin-cli", "GET", "/audit/v1/session-alerts"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/session-alerts/summary"),
		mtlstest.Deny("api-gateway", "POST", "/audit/v1/session-alerts"),
		mtlstest.Deny("rdp-vnc-proxy", "POST", "/audit/v1/session-metadata/attestations"),
		mtlstest.Deny("api-gateway", "GET", "/audit/v1/session-metadata/head"),
		mtlstest.Deny("admin-cli", "POST", "/audit/v1/session-metadata/attestations"),
		mtlstest.Deny("session-broker", "GET", "/audit/v1/session-metadata/attestations"),
		mtlstest.Allow("admin-cli", "GET", "/metrics"),
	})
}

func TestEveryRegisteredRouteHasACaller(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: "GET", Path: "/metrics"},
		{Method: "POST", Path: "/audit/v1/emit-event"},
		{Method: "GET", Path: "/audit/v1/verify-chain"},
		{Method: "GET", Path: "/audit/v1/secret-injections"},
		{Method: "POST", Path: "/audit/v1/session-metadata/attestations"},
		{Method: "GET", Path: "/audit/v1/session-metadata/head"},
		{Method: "GET", Path: "/audit/v1/session-alerts"},
		{Method: "GET", Path: "/audit/v1/session-alerts/summary"},
		{Method: "GET", Path: "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef"},
		{Method: "POST", Path: "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge"},
		{Method: "GET", Path: "/healthz"},
	})
}

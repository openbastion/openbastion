package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Audit Service
// (ADR-0010). A route not listed here is refused to everyone.
//
// The audit trail is only as trustworthy as who may write to it: before mutual
// TLS, anyone who could reach this port could add events in any actor's name.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		// The Command Recorder writes the reads of a recording, before it serves them (ADR-0022).
		{Method: http.MethodPost, Path: "/audit/v1/emit-event", Callers: []string{mtls.SessionBroker, mtls.SSHProxy, mtls.RDPVNCProxy, mtls.CommandRecorder, mtls.PasswordVault, mtls.Authentication, mtls.VideoRecorder, mtls.WorkflowService}},
		// Verifying the chain is an operator's act.
		{Path: "/audit/v1/verify-chain", Callers: []string{mtls.AdminCLI}},
		// Reconciliation is an operator-only read of retained, signed audit evidence. The Gateway
		// is admitted only as a facade; it enforces the verified user policy before this call.
		{Method: http.MethodGet, Path: "/audit/v1/secret-injections", Callers: []string{mtls.AdminCLI, mtls.APIGateway}},
		// The heads of the session metadata (ADR-0116 §4): the Session Broker's only.
		{Method: http.MethodPost, Path: "/audit/v1/session-metadata/attestations", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/audit/v1/session-metadata/head", Callers: []string{mtls.SessionBroker}},
		// The operator projection is read by the Gateway facade after user authorization; acknowledgements are written only by the same facade (ADR-0117/0122).
		{Method: http.MethodGet, Path: "/audit/v1/session-alerts", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/audit/v1/session-alerts/summary", Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/audit/v1/session-alerts/", Prefix: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodPost, Path: "/audit/v1/session-alerts/", Prefix: true, Callers: []string{mtls.APIGateway}},
		{Method: http.MethodGet, Path: "/metrics", Callers: []string{mtls.Any}}, // ADR-0135: pool telemetry
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

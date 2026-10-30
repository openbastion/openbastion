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
		{Method: http.MethodPost, Path: "/audit/v1/emit-event", Callers: []string{mtls.SessionBroker, mtls.SSHProxy, mtls.CommandRecorder}},
		// Verifying the chain is an operator's act.
		{Path: "/audit/v1/verify-chain", Callers: []string{mtls.AdminCLI}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

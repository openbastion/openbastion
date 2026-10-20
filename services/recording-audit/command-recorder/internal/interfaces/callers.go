package interfaces

import (
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Command Recorder
// (ADR-0010). A route not listed here is refused to everyone.
//
// Before mutual TLS, anyone who could reach this port could write entries into a
// session's replay. Now only the proxy that ran the session can, and only the
// Gateway — acting for an auditor it has authenticated — can read them back.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodPost, Path: "/recorder/v1/command-entries", Callers: []string{mtls.SSHProxy}},
		{Method: http.MethodGet, Path: "/recorder/v1/sessions/", Prefix: true, Callers: []string{mtls.APIGateway}},
		// Readiness is asked by the proxy before it admits a session (ADR-0008),
		// and by whatever supervises the recorder.
		{Method: http.MethodGet, Path: "/readyz", Callers: []string{mtls.Any}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

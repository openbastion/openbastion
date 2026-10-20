package interfaces

import (
	"github.com/openbastion/openbastion/pkg/mtls"
)

// CallerRules says which services may call which route of the Session Broker
// (ADR-0010). A route not listed here is refused to everyone.
//
// Sessions are requested, connected to and ended by users, who reach the Broker
// through the Gateway only. The Gateway states who the user is (requestedBy,
// actorRoles); the Broker believes it because nobody else may say it.
func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Path: "/sessions", Callers: []string{mtls.APIGateway}},
		{Path: "/sessions/", Prefix: true, Callers: []string{mtls.APIGateway}},
		{Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

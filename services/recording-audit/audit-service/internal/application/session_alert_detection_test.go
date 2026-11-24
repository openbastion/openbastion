package application

import (
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

func TestMatchSessionAlertRule_RequiresExactAuthenticatedEmitterActionAndFailure(t *testing.T) {
	cases := []struct {
		name  string
		event domain.Event
		want  bool
	}{
		{"breakglass from broker", domain.Event{Emitter: "session-broker", Action: "session.breakglass_requested", ResourceType: "session", Success: true}, true},
		{"ssh injection failure", domain.Event{Emitter: "ssh-proxy", Action: "session.secret_injection_failed", ResourceType: "session", Success: false}, true},
		{"rdp vnc injection failure", domain.Event{Emitter: "rdp-vnc-proxy", Action: "session.secret_injection_failed", ResourceType: "session", Success: false}, true},
		{"no authenticated emitter", domain.Event{Action: "session.breakglass_requested", ResourceType: "session"}, false},
		{"forged emitter", domain.Event{Emitter: "api-gateway", Action: "session.breakglass_requested", ResourceType: "session"}, false},
		{"success is not failure", domain.Event{Emitter: "ssh-proxy", Action: "session.secret_injection_failed", ResourceType: "session", Success: true}, false},
		{"wrong resource", domain.Event{Emitter: "session-broker", Action: "session.breakglass_requested", ResourceType: "account"}, false},
		{"unknown action", domain.Event{Emitter: "session-broker", Action: "session.read", ResourceType: "session"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, got := MatchSessionAlertRule(&tc.event)
			if got != tc.want {
				t.Fatalf("matched = %v, want %v", got, tc.want)
			}
		})
	}
}

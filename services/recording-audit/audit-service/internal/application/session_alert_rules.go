package application

import (
	"fmt"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

const SessionAlertCatalogVersion = "1"

type SessionAlertRule struct {
	ID           string
	Version      string
	Emitter      string
	Action       string
	ResourceType string
	Severity     domain.AlertSeverity
	Summary      string
}

// SessionAlertRules is an immutable server-side catalogue. A rule is enabled only
// for a producer/action pair already present in the authenticated audit contract.
func SessionAlertRules() []SessionAlertRule {
	rules, _ := SessionAlertRulesForVersion(SessionAlertCatalogVersion)
	return rules
}

// SessionAlertRulesForVersion retains immutable catalogues so an outbox item is always
// evaluated with the exact rule set captured when its source event was appended.
func SessionAlertRulesForVersion(version string) ([]SessionAlertRule, bool) {
	switch version {
	case "1":
		return []SessionAlertRule{
			{ID: "session.breakglass-requested", Version: "1", Emitter: mtls.SessionBroker, Action: "session.breakglass_requested", ResourceType: "session", Severity: domain.AlertHigh, Summary: "A break-glass session was requested"},
			{ID: "session.secret-injection-failed.ssh", Version: "1", Emitter: mtls.SSHProxy, Action: "session.secret_injection_failed", ResourceType: "session", Severity: domain.AlertHigh, Summary: "Secret injection failed during an SSH session"},
			{ID: "session.secret-injection-failed.rdp-vnc", Version: "1", Emitter: mtls.RDPVNCProxy, Action: "session.secret_injection_failed", ResourceType: "session", Severity: domain.AlertHigh, Summary: "Secret injection failed during an RDP or VNC session"},
		}, true
	default:
		return nil, false
	}
}

func MatchSessionAlert(event *domain.Event) (SessionAlertRule, bool) {
	rule, matched, _ := MatchSessionAlertForVersion(event, SessionAlertCatalogVersion)
	return rule, matched
}

func MatchSessionAlertForVersion(event *domain.Event, version string) (SessionAlertRule, bool, error) {
	rules, supported := SessionAlertRulesForVersion(version)
	if !supported {
		return SessionAlertRule{}, false, fmt.Errorf("unsupported session alert catalogue version %q", version)
	}
	// A denied break-glass request is still a security-relevant request; its
	// outcome does not suppress the alert.
	for _, rule := range rules {
		if event != nil && event.Emitter == rule.Emitter && event.Action == rule.Action && event.ResourceType == rule.ResourceType {
			if rule.Action == "session.secret_injection_failed" && event.Success {
				return SessionAlertRule{}, false, nil
			}
			return rule, true, nil
		}
	}
	return SessionAlertRule{}, false, nil
}

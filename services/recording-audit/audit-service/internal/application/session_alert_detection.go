package application

import (
	"context"
	"errors"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

const (
	SessionAlertCatalogVersion = "v1"
)

var ErrSessionAlertDetectionUnavailable = errors.New("session alert detection storage unavailable")

// SessionAlertRule is immutable server-side policy. Emitter comes from the authenticated mTLS
// peer at the HTTP boundary, never from an event body.
type SessionAlertRule struct {
	ID, CatalogVersion, Emitter, Action, ResourceType, Severity, Summary string
	RequireFailure                                                       bool
}

var sessionAlertRules = []SessionAlertRule{
	{ID: "session.breakglass_requested", CatalogVersion: SessionAlertCatalogVersion, Emitter: "session-broker", Action: "session.breakglass_requested", ResourceType: "session", Severity: "high", Summary: "Une demande break-glass a été effectuée"},
	{ID: "session.secret_injection_failed.ssh", CatalogVersion: SessionAlertCatalogVersion, Emitter: "ssh-proxy", Action: "session.secret_injection_failed", ResourceType: "session", Severity: "high", Summary: "Une injection de secret SSH a échoué", RequireFailure: true},
	{ID: "session.secret_injection_failed.rdp_vnc", CatalogVersion: SessionAlertCatalogVersion, Emitter: "rdp-vnc-proxy", Action: "session.secret_injection_failed", ResourceType: "session", Severity: "high", Summary: "Une injection de secret écran a échoué", RequireFailure: true},
}

// SessionAlertDetectionStore commits an event and its detection work item atomically.
type SessionAlertDetectionStore interface {
	AppendWithDetection(ctx context.Context, event *domain.Event, catalogVersion string) error
}

// MatchSessionAlertRule returns the immutable server-side rule matching an authenticated event.
func MatchSessionAlertRule(event *domain.Event) (SessionAlertRule, bool) {
	if event == nil || event.Emitter == "" {
		return SessionAlertRule{}, false
	}
	for _, rule := range sessionAlertRules {
		if event.Emitter != rule.Emitter || event.Action != rule.Action || event.ResourceType != rule.ResourceType {
			continue
		}
		if rule.RequireFailure && event.Success {
			continue
		}
		return rule, true
	}
	return SessionAlertRule{}, false
}

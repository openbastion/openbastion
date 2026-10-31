package application

import (
	"context"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// AlertNotifier pushes an alert out of the platform once it is in the chain (ADR-0045). Notify
// is called while the chain is held: it must return at once, and it has no result — the event
// is written whatever becomes of its notification.
type AlertNotifier interface {
	Notify(ctx context.Context, e domain.Event)
}

// alertEmitters says which actions are alerts, and the one service that may raise each
// (ADR-0045): the emitter its certificate names (ADR-0027), never what the request says. The
// names are pkg/mtls's (alerts_test.go holds them to it).
var alertEmitters = map[string]string{
	"vault.rotation_overdue": "password-vault", // ADR-0041
}

// AlertActions lists the actions that are pushed, for the start-up log.
func AlertActions() map[string]string {
	out := make(map[string]string, len(alertEmitters))
	for a, e := range alertEmitters {
		out[a] = e
	}
	return out
}

// WithAlertNotifier pushes every alert written to the chain to n. unnamedAllowed says that
// internal TLS is disabled: no emitter is ever named, and an alert with none is pushed — a
// named emitter must still be the right one.
func (s *AuditService) WithAlertNotifier(n AlertNotifier, unnamedAllowed bool) *AuditService {
	s.alerts, s.alertsUnnamed = n, unnamedAllowed
	return s
}

func (s *AuditService) isAlert(e *domain.Event) bool {
	want, ok := alertEmitters[e.Action]
	if !ok {
		return false
	}
	return e.Emitter == want || e.Emitter == "" && s.alertsUnnamed
}

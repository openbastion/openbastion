package application

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func TestSessionAlertReadsAreBoundedStableAndDoNotExposeSourceDetails(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store)
	fixed := time.Date(2026, 11, 24, 9, 0, 0, 0, time.UTC)
	svc.now = func() time.Time { return fixed }
	for _, sessionID := range []string{"session-a", "session-b", "session-c"} {
		if _, err := svc.EmitEventAsWithDetails(ctx, "session-broker", "operator-1", "session.breakglass_requested", "session", sessionID, map[string]string{"credential": "must-not-be-copied"}, true); err != nil {
			t.Fatal(err)
		}
		if processed, err := svc.ProcessSessionAlertDetections(ctx, 10); err != nil || processed != 1 {
			t.Fatalf("ProcessSessionAlertDetections = %d, %v", processed, err)
		}
	}

	first, err := svc.ListSessionAlerts(ctx, SessionAlertListQuery{Limit: 2, Status: domain.AlertStatusUnacknowledged, Severity: "high"})
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Alerts) != 2 || !first.HasMore || first.NextCursor == "" {
		t.Fatalf("first page = %+v", first)
	}
	second, err := svc.ListSessionAlerts(ctx, SessionAlertListQuery{Limit: 2, Status: domain.AlertStatusUnacknowledged, Severity: "high", Cursor: first.NextCursor})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Alerts) != 1 || second.HasMore || second.Alerts[0].ID == first.Alerts[0].ID || second.Alerts[0].ID == first.Alerts[1].ID {
		t.Fatalf("second page = %+v", second)
	}
	for _, alert := range append(first.Alerts, second.Alerts...) {
		if alert.Summary == "" || alert.Revision != 1 || alert.SourceEventID == "" {
			t.Fatalf("incomplete alert projection: %+v", alert)
		}
	}
	if _, err := svc.ListSessionAlerts(ctx, SessionAlertListQuery{Cursor: "not-a-cursor"}); err != ErrInvalidSessionAlertQuery {
		t.Fatalf("invalid cursor error = %v", err)
	}
	if _, err := svc.ListSessionAlerts(ctx, SessionAlertListQuery{Limit: MaxSessionAlertLimit + 1}); err != ErrInvalidSessionAlertQuery {
		t.Fatalf("oversized page error = %v", err)
	}

	summary, err := svc.SessionAlertSummary(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if summary.UnacknowledgedCount != 3 || summary.BySeverity["high"] != 3 || summary.Durable {
		t.Fatalf("summary = %+v, want three high unacknowledged alerts and durable=false", summary)
	}
	got, err := svc.GetSessionAlert(ctx, first.Alerts[0].ID)
	if err != nil || got.ID != first.Alerts[0].ID {
		t.Fatalf("GetSessionAlert = %+v, %v", got, err)
	}
	if _, err := svc.GetSessionAlert(ctx, "alert_00000000000000000000000000000000"); err != ErrSessionAlertNotFound {
		t.Fatalf("missing alert error = %v", err)
	}
	if _, err := svc.GetSessionAlert(ctx, "../audit_events"); err != ErrInvalidSessionAlertQuery {
		t.Fatalf("invalid id error = %v", err)
	}
}

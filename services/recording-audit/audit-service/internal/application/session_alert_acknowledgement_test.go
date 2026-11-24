package application_test

import (
	"context"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func newAcknowledgementFixture(t *testing.T) (*application.AuditService, *infrastructure.InMemoryStore, domain.SessionAlert) {
	t.Helper()
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAs(ctx, "session-broker", "requester-1", "session.breakglass_requested", "session", "session-ack-test", false); err != nil {
		t.Fatal(err)
	}
	if processed, err := svc.ProcessSessionAlertDetections(ctx, 10); err != nil || processed != 1 {
		t.Fatalf("ProcessSessionAlertDetections = %d, %v", processed, err)
	}
	alerts := store.SessionAlerts()
	if len(alerts) != 1 {
		t.Fatalf("alerts = %d, want 1", len(alerts))
	}
	return svc, store, alerts[0]
}

func TestSessionAlertAcknowledgement_IsAtomicAuditedAndIdempotent(t *testing.T) {
	ctx := context.Background()
	svc, store, alert := newAcknowledgementFixture(t)
	before, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}

	got, already, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-1", alert.ID, alert.Revision)
	if err != nil || already {
		t.Fatalf("acknowledge = %+v, already=%v, err=%v", got, already, err)
	}
	if got.Status != domain.AlertStatusAcknowledged || got.Revision != alert.Revision+1 || got.AcknowledgedBy != "auditor-1" || got.AcknowledgedAt == nil || got.AcknowledgementEventID == "" {
		t.Fatalf("acknowledged projection = %+v", got)
	}
	after, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatalf("audit event count %d, want %d", len(after), len(before)+1)
	}
	event := after[len(after)-1]
	if event.ID != got.AcknowledgementEventID || event.Action != "session.alert.acknowledged" || event.ResourceType != "session_alert" || event.ResourceID != alert.ID || event.ActorID != "auditor-1" || event.Emitter != "api-gateway" || !event.Success {
		t.Fatalf("acknowledgement audit event = %+v", event)
	}
	if event.Details["session_id"] != alert.SessionID || event.Details["rule_id"] != alert.RuleID || event.Details["severity"] != string(alert.Severity) || event.Details["revision"] != "1" {
		t.Fatalf("acknowledgement event details = %+v", event.Details)
	}

	retry, already, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-1", alert.ID, alert.Revision)
	if err != nil || !already || retry.AcknowledgementEventID != got.AcknowledgementEventID {
		t.Fatalf("idempotent retry = %+v, already=%v, err=%v", retry, already, err)
	}
	afterRetry, _ := store.All(ctx)
	if len(afterRetry) != len(after) {
		t.Fatalf("retry appended a second event: %d -> %d", len(after), len(afterRetry))
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("signed chain does not verify: %v", err)
	}
}

func TestSessionAlertAcknowledgement_RejectsStaleRevisionAndUnknownAlert(t *testing.T) {
	ctx := context.Background()
	svc, _, alert := newAcknowledgementFixture(t)
	if _, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-1", alert.ID, alert.Revision+1); err != domain.ErrSessionAlertRevisionConflict {
		t.Fatalf("stale revision error = %v, want conflict", err)
	}
	if _, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-1", "alert_00000000000000000000000000000000", 1); err != domain.ErrSessionAlertNotFound {
		t.Fatalf("unknown alert error = %v, want not found", err)
	}
	if _, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "", alert.ID, alert.Revision); err != application.ErrInvalidSessionAlertAcknowledgement {
		t.Fatalf("empty actor error = %v, want invalid request", err)
	}
}

func TestSessionAlertAcknowledgement_ConcurrentRetriesAppendExactlyOneEvent(t *testing.T) {
	ctx := context.Background()
	svc, store, alert := newAcknowledgementFixture(t)
	before, _ := store.All(ctx)
	const callers = 12
	var wg sync.WaitGroup
	errs := make(chan error, callers)
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := svc.AcknowledgeSessionAlert(ctx, "api-gateway", "auditor-1", alert.ID, alert.Revision)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent acknowledgement: %v", err)
		}
	}
	after, _ := store.All(ctx)
	if len(after) != len(before)+1 {
		t.Fatalf("concurrent callers appended %d events, want exactly 1", len(after)-len(before))
	}
}

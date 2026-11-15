package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

const (
	injectionOne = "0123456789abcdef0123456789abcdef"
	injectionTwo = "1123456789abcdef0123456789abcdef"
)

func emitInjectionEvent(t *testing.T, svc *application.AuditService, emitter, action, session, id, protocol, account string, success bool) {
	t.Helper()
	_, err := svc.EmitEventAsWithDetails(context.Background(), emitter, "operator-1", action, "session", session,
		map[string]string{"injection_id": id, "protocol": protocol, "account_id": account}, success)
	if err != nil {
		t.Fatalf("EmitEventAsWithDetails(%s): %v", action, err)
	}
}

func TestReconcileSecretInjections_ClassifiesOnlyCorrelatedTerminalEvidence(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	for _, event := range []struct {
		action, session, id string
		success             bool
	}{
		{"session.secret_injection_started", "session-complete", injectionOne, true},
		{"session.secret_injected", "session-complete", injectionOne, true},
		{"session.secret_injection_started", "session-failed", injectionTwo, true},
		{"session.secret_injection_failed", "session-failed", injectionTwo, false},
		{"session.secret_injection_started", "session-unknown", "2123456789abcdef0123456789abcdef", true},
	} {
		emitInjectionEvent(t, svc, "ssh-proxy", event.action, event.session, event.id, "ssh", "account-prod", event.success)
	}

	before, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got, err := svc.ReconcileSecretInjections(context.Background(), 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if got.Coverage != "retained_audit_chain" || got.ScannedEvents != len(before) || got.ArchivedHistoryExcluded {
		t.Fatalf("coverage metadata: %+v", got)
	}
	if len(got.Outcomes) != 3 {
		t.Fatalf("got %d outcomes, want 3: %+v", len(got.Outcomes), got.Outcomes)
	}
	byID := make(map[string]application.SecretInjectionOutcome)
	for _, outcome := range got.Outcomes {
		byID[outcome.InjectionID] = outcome
	}
	if byID[injectionOne].Status != "completed" || byID[injectionOne].ResultEvent == "" || byID[injectionOne].SessionID != "session-complete" {
		t.Fatalf("completed outcome: %+v", byID[injectionOne])
	}
	if byID[injectionTwo].Status != "failed" || byID[injectionTwo].ResultEvent == "" || byID[injectionTwo].Reason != "proxy_reported_input_failure_may_be_partial" {
		t.Fatalf("failed outcome: %+v", byID[injectionTwo])
	}
	unknown := byID["2123456789abcdef0123456789abcdef"]
	if unknown.Status != "outcome_unknown" || unknown.Reason != "missing_terminal_event" || unknown.FinishedAt != nil {
		t.Fatalf("unknown outcome: %+v", unknown)
	}
	after, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before) {
		t.Fatalf("reconciliation mutated audit history: %d -> %d", len(before), len(after))
	}
	if err := svc.VerifyChain(context.Background()); err != nil {
		t.Fatalf("reconciliation damaged audit chain: %v", err)
	}
}

func TestReconcileSecretInjections_MarksConflictingEvidenceUnknown(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-a", injectionOne, "ssh", "account-a", true)
	emitInjectionEvent(t, svc, "rdp-vnc-proxy", "session.secret_injected", "session-a", injectionOne, "ssh", "account-a", true)
	got, err := svc.ReconcileSecretInjections(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Outcomes) != 1 || got.Outcomes[0].Status != "outcome_unknown" || got.Outcomes[0].Reason != "evidence_mismatch" {
		t.Fatalf("mismatched emitter must remain unknown: %+v", got.Outcomes)
	}
}

func TestReconcileSecretInjections_DuplicateAndOrphanEvidenceRemainUnknown(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-a", injectionOne, "ssh", "account-a", true)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-a", injectionOne, "ssh", "account-a", true)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injected", "session-b", injectionTwo, "ssh", "account-b", true)
	got, err := svc.ReconcileSecretInjections(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	byID := map[string]application.SecretInjectionOutcome{}
	for _, outcome := range got.Outcomes {
		byID[outcome.InjectionID] = outcome
	}
	if byID[injectionOne].Status != "outcome_unknown" || byID[injectionOne].Reason != "duplicate_start_event" {
		t.Fatalf("duplicate start: %+v", byID[injectionOne])
	}
	if byID[injectionTwo].Status != "outcome_unknown" || byID[injectionTwo].Reason != "missing_start_event" {
		t.Fatalf("orphan result: %+v", byID[injectionTwo])
	}
}

func TestReconcileSecretInjections_LimitIsBoundedAndNewestFirst(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	for _, id := range []string{injectionOne, injectionTwo} {
		emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-"+id, id, "ssh", "account-a", true)
	}
	got, err := svc.ReconcileSecretInjections(context.Background(), 1, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Outcomes) != 1 || !got.HasMore || got.NextBefore != got.Outcomes[0].InjectionID {
		t.Fatalf("limit/cursor ignored: %+v", got)
	}
	next, err := svc.ReconcileSecretInjections(context.Background(), 1, got.NextBefore)
	if err != nil || len(next.Outcomes) != 1 || next.HasMore || next.Outcomes[0].InjectionID == got.Outcomes[0].InjectionID {
		t.Fatalf("second page: %+v, %v", next, err)
	}
	if _, err := svc.ReconcileSecretInjections(context.Background(), 1, "ffffffffffffffffffffffffffffffff"); !errors.Is(err, application.ErrReconciliationCursorNotFound) {
		t.Fatalf("missing cursor error = %v", err)
	}
	if _, err := svc.ReconcileSecretInjections(context.Background(), 501, ""); err == nil {
		t.Fatal("limit above maximum was accepted")
	}
}

func TestReconcileSecretInjections_DoesNotAcceptMalformedIDs(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-a", "ABCDEF0123456789ABCDEF0123456789", "ssh", "account-a", true)
	got, err := svc.ReconcileSecretInjections(context.Background(), 10, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Outcomes) != 0 {
		t.Fatalf("malformed ID was accepted: %+v", got.Outcomes)
	}
}

type checkpointSource struct {
	checkpoints []domain.Checkpoint
	err         error
}

func (c checkpointSource) Append(context.Context, domain.Anchor) error               { return nil }
func (c checkpointSource) All(context.Context) ([]domain.Anchor, error)              { return nil, nil }
func (c checkpointSource) AppendCheckpoint(context.Context, domain.Checkpoint) error { return nil }
func (c checkpointSource) Checkpoints(context.Context) ([]domain.Checkpoint, error) {
	return c.checkpoints, c.err
}

func TestReconcileSecretInjections_FailsClosedWhenArchiveCheckpointsCannotBeRead(t *testing.T) {
	svc := application.NewAuditService(infrastructure.NewInMemoryStore()).WithAnchors(checkpointSource{err: context.DeadlineExceeded})
	if _, err := svc.ReconcileSecretInjections(context.Background(), 10, ""); err == nil {
		t.Fatal("unreadable checkpoints returned a partial reconciliation")
	}
}

func TestReconcileSecretInjections_RefusesTamperedAuditChain(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	emitInjectionEvent(t, svc, "ssh-proxy", "session.secret_injection_started", "session-a", injectionOne, "ssh", "account-a", true)
	events, err := store.All(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	events[0].ResourceID = "session-tampered"
	if _, err := svc.ReconcileSecretInjections(context.Background(), 10, ""); err == nil {
		t.Fatal("reconciliation accepted a tampered audit chain")
	}
}

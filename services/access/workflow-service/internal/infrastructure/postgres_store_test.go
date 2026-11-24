package infrastructure_test

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/dbpool"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
)

func isolatedStore(t *testing.T) *infrastructure.PostgresStore {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set — PostgreSQL integration test skipped")
	}
	db, err := infrastructure.OpenPostgres(context.Background(), base, dbpool.Defaults())
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	// The test database is dedicated to the suite. Reset only Workflow-owned rows;
	// never touch another service's tables from this service's tests.
	if _, err := db.Exec(`TRUNCATE workflow_approvals, workflow_requests, approver_hierarchy, workflow_audit_outbox; UPDATE approval_hierarchy_state SET revision = 0 WHERE singleton = TRUE`); err != nil {
		t.Fatalf("reset Workflow test rows: %v", err)
	}
	return infrastructure.NewPostgresStore(db)
}

func TestPostgresHierarchyRevisionCycleAndAuditOutbox(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	revision, err := store.HierarchyRevision(ctx)
	if err != nil || revision != 0 {
		t.Fatalf("initial revision=%d err=%v", revision, err)
	}

	event := domain.AuditOutboxEvent{ID: "event-set-" + fmt.Sprint(now.UnixNano()), ActorID: "user_admin", Action: "approval_hierarchy.relation_changed", ResourceType: "approval_hierarchy", ResourceID: "user_a", Details: map[string]string{"subordinate_user_id": "user_a", "manager_user_id": "user_b"}, Success: true}
	relation, changed, err := store.SetManager(ctx, "user_a", "user_b", 0, now, event)
	if err != nil || !changed || relation.Revision != 1 {
		t.Fatalf("SetManager relation=%+v changed=%v err=%v", relation, changed, err)
	}

	got, snapshot, err := store.GetManager(ctx, "user_a")
	if err != nil || snapshot != 1 || got.ManagerUserID != "user_b" {
		t.Fatalf("GetManager got=%+v revision=%d err=%v", got, snapshot, err)
	}
	page, err := store.ListHierarchy(ctx, "user_b", 1, 10)
	if err != nil || page.TotalItems != 1 || page.Revision != 1 || len(page.Items) != 1 {
		t.Fatalf("ListHierarchy page=%+v err=%v", page, err)
	}

	// A same-manager write is idempotent and does not add an outbox event.
	_, changed, err = store.SetManager(ctx, "user_a", "user_b", 1, now, domain.AuditOutboxEvent{ID: "event-noop", ActorID: "user_admin"})
	if err != nil || changed {
		t.Fatalf("same-manager write changed=%v err=%v", changed, err)
	}
	if _, _, err := store.SetManager(ctx, "user_b", "user_a", 1, now, domain.AuditOutboxEvent{ID: "event-cycle", ActorID: "user_admin"}); !errors.Is(err, domain.ErrCycle) {
		t.Fatalf("cycle error=%v", err)
	}
	if _, _, err := store.SetManager(ctx, "user_c", "user_b", 0, now, domain.AuditOutboxEvent{ID: "event-stale", ActorID: "user_admin"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale revision error=%v", err)
	}

	revision, changed, err = store.DeleteManager(ctx, "user_a", 1, now.Add(time.Second), domain.AuditOutboxEvent{ID: "event-delete", ActorID: "user_admin", Action: "approval_hierarchy.relation_changed", ResourceType: "approval_hierarchy", ResourceID: "user_a", Details: map[string]string{"operation": "delete"}, Success: true})
	if err != nil || !changed || revision != 2 {
		t.Fatalf("DeleteManager revision=%d changed=%v err=%v", revision, changed, err)
	}
	if _, _, err := store.GetManager(ctx, "user_a"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("deleted relation error=%v", err)
	}

	events, err := store.ClaimAuditEvents(ctx, now.Add(2*time.Second), 30*time.Second, 10)
	if err != nil || len(events) != 2 {
		t.Fatalf("claimed outbox events=%d err=%v", len(events), err)
	}
	for _, event := range events {
		if event.LeaseToken == "" || event.LeaseUntil == nil || event.Attempts != 1 {
			t.Fatalf("event not leased: %+v", event)
		}
		if err := store.CompleteAuditEvent(ctx, event.ID, event.LeaseToken); err != nil {
			t.Fatalf("CompleteAuditEvent: %v", err)
		}
	}
	remaining, err := store.ClaimAuditEvents(ctx, now.Add(time.Minute), 30*time.Second, 10)
	if err != nil || len(remaining) != 0 {
		t.Fatalf("completed events reappeared: %d err=%v", len(remaining), err)
	}
}

func TestPostgresHierarchyConcurrentWritesCannotCreateCycle(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()
	revision, err := store.HierarchyRevision(ctx)
	if err != nil {
		t.Fatal(err)
	}
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, pair := range [][2]string{{"user_x", "user_y"}, {"user_y", "user_x"}} {
		pair := pair
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := store.SetManager(ctx, pair[0], pair[1], revision, time.Now().UTC(), domain.AuditOutboxEvent{ID: "event-" + pair[0], ActorID: "user_admin", Details: map[string]string{}})
			results <- err
		}()
	}
	close(start)
	wg.Wait()
	close(results)
	successes, conflicts := 0, 0
	for err := range results {
		if err == nil {
			successes++
		} else if errors.Is(err, domain.ErrConflict) {
			conflicts++
		} else {
			t.Fatalf("unexpected result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successes=%d conflicts=%d", successes, conflicts)
	}
}

func TestPostgresApprovalRequestIdempotencyDecisionCancelAndExpiry(t *testing.T) {
	store := isolatedStore(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	if _, changed, err := store.SetManager(ctx, "user_requester", "user_approver", 0, now, domain.AuditOutboxEvent{ID: "hierarchy-event", ActorID: "user_admin", Details: map[string]string{}}); err != nil || !changed {
		t.Fatalf("SetManager changed=%v err=%v", changed, err)
	}

	input := domain.CreateApprovalInput{RequestID: "session_pg_1", ResourceType: "session", ResourceID: "session_pg_1", RequesterUserID: "user_requester", AccountID: "acct_1", TicketReference: "CHG-1", DecisionExpiresAt: now.Add(10 * time.Minute), IdempotencyKey: "session_pg_1"}
	hash := sha256.Sum256([]byte("stable request"))
	event := domain.AuditOutboxEvent{ID: "approval-event-1", ActorID: "user_requester", Action: "workflow.approval_requested", ResourceType: "session", ResourceID: input.ResourceID, Details: map[string]string{}, Success: true}
	created, inserted, err := store.CreateApprovalRequest(ctx, input, "user_approver", 1, hash, now, event)
	if err != nil || !inserted || created.ApproverUserID != "user_approver" || created.Revision != 1 {
		t.Fatalf("create: request=%+v inserted=%v err=%v", created, inserted, err)
	}
	duplicate, inserted, err := store.CreateApprovalRequest(ctx, input, "user_changed_manager", 1, hash, now, domain.AuditOutboxEvent{ID: "duplicate-event"})
	if err != nil || inserted || duplicate.ApproverUserID != "user_approver" {
		t.Fatalf("idempotent duplicate: request=%+v inserted=%v err=%v", duplicate, inserted, err)
	}
	badHash := sha256.Sum256([]byte("different request"))
	if _, _, err := store.CreateApprovalRequest(ctx, input, "user_approver", 1, badHash, now, domain.AuditOutboxEvent{ID: "bad-hash"}); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("idempotency mismatch: %v", err)
	}

	page, err := store.ListPendingApprovals(ctx, "user_approver", 1, 10, now)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != input.RequestID {
		t.Fatalf("pending page: %+v err=%v", page, err)
	}
	decided, changed, err := store.DecideApprovalRequest(ctx, input.RequestID, 1, domain.ApprovalApproved, "user_approver", "approved", now.Add(time.Second), domain.AuditOutboxEvent{ID: "approval-event-2", ActorID: "user_approver", Action: "workflow.approval_decided", ResourceType: "session", ResourceID: input.ResourceID, Details: map[string]string{}, Success: true})
	if err != nil || !changed || decided.Status != domain.ApprovalApproved || decided.Revision != 2 {
		t.Fatalf("decide: request=%+v changed=%v err=%v", decided, changed, err)
	}
	duplicateDecision, changed, err := store.DecideApprovalRequest(ctx, input.RequestID, 1, domain.ApprovalApproved, "user_approver", "approved", now.Add(2*time.Second), domain.AuditOutboxEvent{ID: "duplicate-decision"})
	if err != nil || changed || duplicateDecision.Revision != 2 {
		t.Fatalf("idempotent decision: request=%+v changed=%v err=%v", duplicateDecision, changed, err)
	}

	cancelInput := domain.CreateApprovalInput{RequestID: "session_pg_2", ResourceType: "session", ResourceID: "session_pg_2", RequesterUserID: "user_requester", AccountID: "acct_1", TicketReference: "CHG-2", DecisionExpiresAt: now.Add(10 * time.Minute), IdempotencyKey: "session_pg_2"}
	if _, _, err := store.CreateApprovalRequest(ctx, cancelInput, "user_approver", 1, sha256.Sum256([]byte("cancel")), now, domain.AuditOutboxEvent{ID: "approval-event-3", ActorID: "user_requester", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	cancelled, changed, err := store.CancelApprovalRequest(ctx, cancelInput.RequestID, 1, "session_expired", now.Add(2*time.Second), domain.AuditOutboxEvent{ID: "approval-event-4", Action: "workflow.approval_request_cancelled", ResourceType: "session", ResourceID: cancelInput.ResourceID, Details: map[string]string{}, Success: true})
	if err != nil || !changed || cancelled.Status != domain.ApprovalCancelled || cancelled.Revision != 2 {
		t.Fatalf("cancel: request=%+v changed=%v err=%v", cancelled, changed, err)
	}

	expireInput := domain.CreateApprovalInput{RequestID: "session_pg_3", ResourceType: "session", ResourceID: "session_pg_3", RequesterUserID: "user_requester", AccountID: "acct_1", TicketReference: "CHG-3", DecisionExpiresAt: now.Add(time.Second), IdempotencyKey: "session_pg_3"}
	if _, _, err := store.CreateApprovalRequest(ctx, expireInput, "user_approver", 1, sha256.Sum256([]byte("expire")), now, domain.AuditOutboxEvent{ID: "approval-event-5", ActorID: "user_requester", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	count, err := store.ExpirePendingApprovals(ctx, now.Add(2*time.Second), 10)
	if err != nil || count != 1 {
		t.Fatalf("ExpirePendingApprovals count=%d err=%v", count, err)
	}
	expired, err := store.GetApprovalRequest(ctx, expireInput.RequestID)
	if err != nil || expired.Status != domain.ApprovalExpired || expired.Revision != 2 {
		t.Fatalf("expired request: %+v err=%v", expired, err)
	}
}

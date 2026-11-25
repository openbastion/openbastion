package application_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/application"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
	"github.com/openbastion/openbastion/services/access/workflow-service/internal/infrastructure"
)

type usersFake map[string]domain.UserAuthorizationContext

func (f usersFake) GetAuthorizationContext(_ context.Context, id string) (domain.UserAuthorizationContext, error) {
	if user, ok := f[id]; ok {
		return user, nil
	}
	return domain.UserAuthorizationContext{UserID: id, Roles: []string{}}, nil
}

type authzFake struct {
	allow bool
	err   error
}

func (f authzFake) CheckAccess(context.Context, string, []string, string, string) (bool, string, error) {
	return f.allow, "policy result", f.err
}

type auditFake struct {
	mu     sync.Mutex
	events []string
	err    error
}

func (f *auditFake) EmitEvent(_ context.Context, _, action, _, _ string, _ map[string]string, _ bool) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.events = append(f.events, action)
	return f.err
}

func activeUsers(ids ...string) usersFake {
	out := usersFake{}
	out["user_admin"] = domain.UserAuthorizationContext{UserID: "user_admin", Exists: true, Active: true, Roles: []string{"platform-admin"}}
	for _, id := range ids {
		out[id] = domain.UserAuthorizationContext{UserID: id, Exists: true, Active: true, Roles: []string{"operator"}}
	}
	return out
}

func TestHierarchy_SetManagerSnapshotsRevisionAndIsIdempotent(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	audit := &auditFake{}
	clock := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	svc := application.NewHierarchyService(store, activeUsers("user_a", "user_b"), authzFake{allow: true}, audit).WithClock(func() time.Time { return clock })

	relation, revision, err := svc.SetManager(context.Background(), "user_admin", []string{"platform-admin"}, "user_a", "user_b", 0)
	if err != nil {
		t.Fatal(err)
	}
	if revision != 1 || relation.ManagerUserID != "user_b" || relation.Revision != 1 {
		t.Fatalf("unexpected relation/revision: %+v, %d", relation, revision)
	}
	if len(audit.events) != 1 || audit.events[0] != "approval_hierarchy.change_authorized" {
		t.Fatalf("pre-mutation audit missing: %v", audit.events)
	}

	// A no-op assignment does not advance the global revision or enqueue a second change.
	relation, revision, err = svc.SetManager(context.Background(), "user_admin", []string{"platform-admin"}, "user_a", "user_b", 1)
	if err != nil || revision != 1 || relation.Revision != 1 {
		t.Fatalf("idempotent assignment: relation=%+v revision=%d err=%v", relation, revision, err)
	}
}

func TestHierarchy_RefusesWithoutAuthorizationOrPreAudit(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	audit := &auditFake{}
	svc := application.NewHierarchyService(store, activeUsers("user_a", "user_b"), authzFake{allow: false}, audit)
	if _, _, err := svc.SetManager(context.Background(), "user_admin", []string{"viewer"}, "user_a", "user_b", 0); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected authorization refusal, got %v", err)
	}
	revision, _ := store.HierarchyRevision(context.Background())
	if revision != 0 {
		t.Fatalf("unauthorized mutation changed hierarchy revision: %d", revision)
	}
}

func TestHierarchy_AuditFailurePreventsMutation(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	audit := &auditFake{err: errors.New("audit offline")}
	svc := application.NewHierarchyService(store, activeUsers("user_a", "user_b"), authzFake{allow: true}, audit)
	if _, _, err := svc.SetManager(context.Background(), "user_admin", []string{"platform-admin"}, "user_a", "user_b", 0); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected audit failure to fail closed, got %v", err)
	}
	revision, _ := store.HierarchyRevision(context.Background())
	if revision != 0 {
		t.Fatalf("audit failure mutated hierarchy revision: %d", revision)
	}
}

func TestHierarchy_InactiveOrUnknownManagerIsRefused(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	users := activeUsers("user_a")
	svc := application.NewHierarchyService(store, users, authzFake{allow: true}, &auditFake{})
	if _, _, err := svc.SetManager(context.Background(), "user_admin", []string{"platform-admin"}, "user_a", "user_missing", 1); !errors.Is(err, domain.ErrInvalid) {
		t.Fatalf("unknown manager was not refused: %v", err)
	}
}

func TestMemoryStore_ConcurrentMutationsCannotCreateCycle(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	start := make(chan struct{})
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, pair := range [][2]string{{"user_a", "user_b"}, {"user_b", "user_a"}} {
		pair := pair
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, _, err := store.SetManager(context.Background(), pair[0], pair[1], 0, time.Now().UTC(), domain.AuditOutboxEvent{ID: "event-" + pair[0], ActorID: "user_admin", Details: map[string]string{}})
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
			t.Fatalf("unexpected concurrent result: %v", err)
		}
	}
	if successes != 1 || conflicts != 1 {
		t.Fatalf("successful mutations=%d conflicts=%d, want one each", successes, conflicts)
	}
}

func TestAuditOutboxDispatcherDeliversPostCommitEvent(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	audit := &auditFake{}
	svc := application.NewHierarchyService(store, activeUsers("user_a", "user_b"), authzFake{allow: true}, audit)
	if _, _, err := svc.SetManager(context.Background(), "user_admin", []string{"platform-admin"}, "user_a", "user_b", 0); err != nil {
		t.Fatal(err)
	}
	dispatcher := application.NewAuditOutboxDispatcher(store, audit)
	if err := dispatcher.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 2 || audit.events[0] != "approval_hierarchy.change_authorized" || audit.events[1] != "approval_hierarchy.relation_changed" {
		t.Fatalf("pre/post audit events = %v", audit.events)
	}
	if err := dispatcher.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(audit.events) != 2 {
		t.Fatalf("completed event was delivered again: %v", audit.events)
	}
}

func TestApprovalRequest_ResolvesManagerSnapshotsHierarchyAndIsIdempotent(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	now := time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)
	users := activeUsers("user_a", "user_b", "user_c")
	audit := &auditFake{}
	if _, _, err := store.SetManager(context.Background(), "user_a", "user_b", 0, now, domain.AuditOutboxEvent{ID: "hierarchy-1", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	service := application.NewApprovalService(store, store, users, authzFake{allow: true}, audit).WithClock(func() time.Time { return now })
	input := domain.CreateApprovalInput{RequestID: "session_123", ResourceType: "session", ResourceID: "session_123", RequesterUserID: "user_a", AccountID: "acct_123", TicketReference: "CHG-123", DecisionExpiresAt: now.Add(10 * time.Minute), IdempotencyKey: "session_123"}

	created, err := service.CreateApprovalRequest(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if created.ApproverUserID != "user_b" || created.HierarchyRevision != 1 || created.Status != domain.ApprovalPending || created.Revision != 1 {
		t.Fatalf("created request: %+v", created)
	}

	// Changing the hierarchy after request creation cannot silently reassign the pending approval.
	if _, _, err := store.SetManager(context.Background(), "user_a", "user_c", 1, now.Add(time.Second), domain.AuditOutboxEvent{ID: "hierarchy-2", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	replayed, err := service.CreateApprovalRequest(context.Background(), input)
	if err != nil || replayed.ApproverUserID != "user_b" || replayed.HierarchyRevision != 1 {
		t.Fatalf("idempotent replay changed snapshot: %+v err=%v", replayed, err)
	}
	changed := input
	changed.TicketReference = "CHG-456"
	if _, err := service.CreateApprovalRequest(context.Background(), changed); !errors.Is(err, domain.ErrIdempotencyConflict) {
		t.Fatalf("idempotency content conflict: %v", err)
	}
}

func TestApprovalRequest_RequiresConfiguredActiveAndAuthorizedNPlusOne(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	now := time.Now().UTC()
	service := application.NewApprovalService(store, store, activeUsers("user_a", "user_b"), authzFake{allow: true}, &auditFake{}).WithClock(func() time.Time { return now })
	input := domain.CreateApprovalInput{RequestID: "session_no_manager", ResourceType: "session", ResourceID: "session_no_manager", RequesterUserID: "user_a", AccountID: "acct_123", TicketReference: "CHG-123", DecisionExpiresAt: now.Add(5 * time.Minute), IdempotencyKey: "session_no_manager"}
	if _, err := service.CreateApprovalRequest(context.Background(), input); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("missing N+1 must fail closed: %v", err)
	}

	if _, _, err := store.SetManager(context.Background(), "user_a", "user_b", 0, now, domain.AuditOutboxEvent{ID: "hierarchy", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	denied := application.NewApprovalService(store, store, activeUsers("user_a", "user_b"), authzFake{allow: false}, &auditFake{}).WithClock(func() time.Time { return now })
	if _, err := denied.CreateApprovalRequest(context.Background(), input); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("unauthorized N+1 must fail closed: %v", err)
	}
}

func TestApprovalRequest_ListDecisionAndIdempotentDecision(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	now := time.Now().UTC()
	users := activeUsers("user_a", "user_b")
	audit := &auditFake{}
	if _, _, err := store.SetManager(context.Background(), "user_a", "user_b", 0, now, domain.AuditOutboxEvent{ID: "hierarchy", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	service := application.NewApprovalService(store, store, users, authzFake{allow: true}, audit).WithClock(func() time.Time { return now })
	input := domain.CreateApprovalInput{RequestID: "session_decide", ResourceType: "session", ResourceID: "session_decide", RequesterUserID: "user_a", AccountID: "acct_123", TicketReference: "CHG-123", DecisionExpiresAt: now.Add(5 * time.Minute), IdempotencyKey: "session_decide"}
	if _, err := service.CreateApprovalRequest(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	page, err := service.ListPendingApprovals(context.Background(), "user_b", []string{"stale-role"}, 1, 10)
	if err != nil || len(page.Items) != 1 || page.Items[0].ID != input.RequestID {
		t.Fatalf("pending list: %+v err=%v", page, err)
	}
	decided, err := service.DecideApprovalRequest(context.Background(), input.RequestID, "user_b", nil, 1, domain.ApprovalApproved, "approved for change")
	if err != nil || decided.Status != domain.ApprovalApproved || decided.DecidedBy != "user_b" {
		t.Fatalf("decision: %+v err=%v", decided, err)
	}
	replayed, err := service.DecideApprovalRequest(context.Background(), input.RequestID, "user_b", nil, 1, domain.ApprovalApproved, "approved for change")
	if err != nil || replayed.Revision != 2 {
		t.Fatalf("idempotent decision: %+v err=%v", replayed, err)
	}
	if _, err := service.DecideApprovalRequest(context.Background(), input.RequestID, "user_b", nil, 2, domain.ApprovalRejected, "opposite"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("opposite decision must conflict: %v", err)
	}
}

func TestApprovalRequest_ExpiredRequestCannotBeApproved(t *testing.T) {
	store := infrastructure.NewMemoryStore()
	now := time.Now().UTC()
	if _, _, err := store.SetManager(context.Background(), "user_a", "user_b", 0, now, domain.AuditOutboxEvent{ID: "hierarchy", ActorID: "user_admin", Details: map[string]string{}}); err != nil {
		t.Fatal(err)
	}
	service := application.NewApprovalService(store, store, activeUsers("user_a", "user_b"), authzFake{allow: true}, &auditFake{}).WithClock(func() time.Time { return now })
	input := domain.CreateApprovalInput{RequestID: "session_expire", ResourceType: "session", ResourceID: "session_expire", RequesterUserID: "user_a", AccountID: "acct_123", TicketReference: "CHG-123", DecisionExpiresAt: now.Add(time.Minute), IdempotencyKey: "session_expire"}
	if _, err := service.CreateApprovalRequest(context.Background(), input); err != nil {
		t.Fatal(err)
	}
	service.WithClock(func() time.Time { return now.Add(2 * time.Minute) })
	if _, err := service.DecideApprovalRequest(context.Background(), input.RequestID, "user_b", nil, 1, domain.ApprovalApproved, "late"); !errors.Is(err, domain.ErrExpired) {
		t.Fatalf("expired approval decision: %v", err)
	}
	request, err := service.GetApprovalRequest(context.Background(), input.RequestID)
	if err != nil || request.Status != domain.ApprovalExpired {
		t.Fatalf("expired request state: %+v err=%v", request, err)
	}
}

package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

func TestWorkflowDispatch_IsDurableAndApprovalIsInvisibleUntilAssignment(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", goodTicket, 45)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := f.store.HasPendingWorkflowDispatches(context.Background())
	if err != nil || !pending {
		t.Fatalf("durable dispatch pending=%v err=%v", pending, err)
	}
	if _, _, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("approval queue must fail closed during unresolved dispatch: %v", err)
	}
	if notifier.count() != 0 {
		t.Fatalf("approver was notified before Workflow assigned the request: %+v", notifier.got)
	}

	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, err = f.store.HasPendingWorkflowDispatches(context.Background())
	if err != nil || pending {
		t.Fatalf("completed dispatch pending=%v err=%v", pending, err)
	}
	if len(f.workflow.creates) != 1 || f.workflow.creates[0].RequestID != sess.ID || f.workflow.creates[0].RequesterUserID != requester || f.workflow.creates[0].IdempotencyKey != sess.ID {
		t.Fatalf("Workflow request was not derived from the durable session: %+v", f.workflow.creates)
	}
	if notifier.count() != 1 || notifier.got[0].Event != domain.NotifyApprovalRequested {
		t.Fatalf("assignment notification: %+v", notifier.got)
	}
	items, total, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20)
	if err != nil || total != 1 || len(items) != 1 || items[0].ID != sess.ID {
		t.Fatalf("assigned approval queue: %v total=%d err=%v", ids(items), total, err)
	}
}

func TestWorkflowDispatch_TransientFailureRetriesWithBackoff(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	f.workflow.createErr = domain.ErrUnavailable
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", goodTicket, 45)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ := f.store.HasPendingWorkflowDispatches(context.Background())
	if !pending || f.stored(t, sess.ID).Status != domain.StatusPendingApproval || notifier.count() != 0 {
		t.Fatal("transient Workflow failure did not leave a hidden pending dispatch")
	}
	f.clock.advance(3 * time.Second)
	f.workflow.createErr = nil
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ = f.store.HasPendingWorkflowDispatches(context.Background())
	if pending || notifier.count() != 1 {
		t.Fatalf("retry did not complete: pending=%v notifications=%d", pending, notifier.count())
	}
}

func TestWorkflowDispatch_PermanentRefusalIsAuditedAndDeniedClosed(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	f.workflow.createErr = domain.ErrWorkflowPermanent
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", goodTicket, 45)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := f.stored(t, sess.ID); got.Status != domain.StatusDenied {
		t.Fatalf("permanent refusal left session %s", got.Status)
	}
	if !f.audit.has("session.approval_request_failed", false) {
		t.Fatalf("refusal audit missing: %+v", f.audit.events)
	}
	pending, _ := f.store.HasPendingWorkflowDispatches(context.Background())
	if pending || notifier.count() != 0 {
		t.Fatalf("failed assignment remains pending=%v notifications=%d", pending, notifier.count())
	}
}

func TestWorkflowDispatch_LateDeliveryNeverCreatesAnApproval(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", goodTicket, 45)
	if err != nil {
		t.Fatal(err)
	}
	f.clock.advance(application.DefaultBreakGlassApprovalWindow + time.Second)
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.workflow.creates) != 0 {
		t.Fatalf("expired session was dispatched: %+v", f.workflow.creates)
	}
	pending, _ := f.store.HasPendingWorkflowDispatches(context.Background())
	if pending || notifier.count() != 0 {
		t.Fatalf("late dispatch not cleaned: pending=%v notifications=%d", pending, notifier.count())
	}
	if f.stored(t, sess.ID).EffectiveStatus(f.clock.Now()) != domain.StatusExpired {
		t.Fatal("session did not remain expired")
	}
}

func TestWorkflowDispatch_AuditFailureKeepsPermanentRefusalForRetry(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, sessionApproveRes)
	f.workflow.createErr = domain.ErrWorkflowPermanent
	f.audit.failOn = "session.approval_request_failed"
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", goodTicket, 45)
	if err != nil {
		t.Fatal(err)
	}
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ := f.store.HasPendingWorkflowDispatches(context.Background())
	if !pending || f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("session was denied without the refusal audit")
	}
	f.audit.failOn = ""
	f.clock.advance(3 * time.Second)
	if err := f.broker.DispatchWorkflowOutbox(context.Background()); err != nil {
		t.Fatal(err)
	}
	pending, _ = f.store.HasPendingWorkflowDispatches(context.Background())
	if pending || f.stored(t, sess.ID).Status != domain.StatusDenied {
		t.Fatal("audited permanent refusal was not applied")
	}
}

func TestWorkflowDecision_IsAppliedToBrokerSessionByCAS(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess := f.asked(t)
	f.clock.advance(3 * time.Minute)
	approved, err := f.approve(sess.ID, approver)
	if err != nil || approved.Status != domain.StatusActive || approved.DecidedBy != approver {
		t.Fatalf("approve: %+v err=%v", approved, err)
	}
	if want := f.clock.Now().Add(45 * time.Minute); !approved.ExpiresAt.Equal(want) {
		t.Fatalf("duration begins at decision: got=%v want=%v", approved.ExpiresAt, want)
	}
	if notifier.got[len(notifier.got)-1].Event != domain.NotifyApprovalApproved {
		t.Fatalf("approval notification: %+v", notifier.got)
	}
}

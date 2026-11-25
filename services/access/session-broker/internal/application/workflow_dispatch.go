package application

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const (
	workflowDispatchInterval    = 2 * time.Second
	workflowDispatchLease       = 30 * time.Second
	workflowDispatchBatch       = 50
	workflowDispatchMaxTries    = 10
	workflowDispatchPassTimeout = 25 * time.Second
)

// RunWorkflowDispatch is the Session Broker's durable at-least-once outbox worker.
// It never holds a PostgreSQL transaction while calling Workflow Service.
func (s *SessionBrokerService) RunWorkflowDispatch(ctx context.Context) {
	ticker := time.NewTicker(workflowDispatchInterval)
	defer ticker.Stop()
	for {
		passCtx, cancel := context.WithTimeout(ctx, workflowDispatchPassTimeout)
		err := s.DispatchWorkflowOutbox(passCtx)
		cancel()
		if err != nil && ctx.Err() == nil {
			log.Printf("session-broker: Workflow outbox drain failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *SessionBrokerService) DispatchWorkflowOutbox(ctx context.Context) error {
	if s.workflow == nil {
		return domain.ErrUnavailable
	}
	now := s.clock()
	items, err := s.sessions.ClaimWorkflowDispatches(ctx, now, workflowDispatchLease, workflowDispatchBatch)
	if err != nil {
		return err
	}
	for _, item := range items {
		if err := s.dispatchWorkflowItem(ctx, item, now); err != nil {
			log.Printf("session-broker: Workflow dispatch for session %s failed: %v", item.SessionID, err)
		}
	}
	return nil
}

func (s *SessionBrokerService) dispatchWorkflowItem(ctx context.Context, item domain.WorkflowDispatch, now time.Time) error {
	sess, err := s.sessions.Get(ctx, item.SessionID)
	if err != nil {
		return s.retryWorkflowDispatch(ctx, item, "session_unavailable", err)
	}
	if sess.BreakGlass || !sess.ApprovalRequired {
		return s.failWorkflowDispatch(ctx, item, sess, "invalid_dispatch_session", domain.ErrWorkflowPermanent)
	}
	if sess.Status != domain.StatusPendingApproval || !sess.ExpiresAt.After(now) {
		return s.cancelAndCompleteWorkflowDispatch(ctx, item, sess, now)
	}

	input := domain.WorkflowApprovalInput{
		RequestID: sess.ID, ResourceType: "session", ResourceID: sess.ID,
		RequesterUserID: sess.RequestedBy, AccountID: sess.PrivilegedAccountID,
		TicketReference: sess.Ticket, DecisionExpiresAt: sess.ExpiresAt, IdempotencyKey: sess.ID,
	}
	request, err := s.workflow.CreateApprovalRequest(ctx, input)
	if err != nil {
		if errors.Is(err, domain.ErrWorkflowPermanent) || item.Attempts >= workflowDispatchMaxTries {
			return s.failWorkflowDispatch(ctx, item, sess, workflowDispatchErrorCode(err, item.Attempts), err)
		}
		return s.retryWorkflowDispatch(ctx, item, workflowDispatchErrorCode(err, item.Attempts), err)
	}

	// Re-read after the remote commit. The session may have expired or been
	// terminated while the network call was in flight; a late assignment is cancelled.
	current, err := s.sessions.Get(ctx, item.SessionID)
	if err != nil {
		return s.retryWorkflowDispatch(ctx, item, "session_recheck_unavailable", err)
	}
	if current.Status != domain.StatusPendingApproval || !current.ExpiresAt.After(s.clock()) {
		return s.cancelWorkflowRequestAndComplete(ctx, item, request, current)
	}
	if err := s.sessions.CompleteWorkflowDispatch(ctx, item.SessionID, item.LeaseToken); err != nil {
		return err
	}
	s.notify(ctx, domain.ApprovalNotification{
		Event: domain.NotifyApprovalRequested, SessionID: current.ID, AccountID: current.PrivilegedAccountID,
		RequestedBy:     current.RequestedBy,
		DurationMinutes: current.DurationMinutes, Ticket: current.Ticket, ExpiresAt: current.ExpiresAt, At: s.clock(),
	})
	return nil
}

func (s *SessionBrokerService) cancelAndCompleteWorkflowDispatch(ctx context.Context, item domain.WorkflowDispatch, sess *domain.Session, now time.Time) error {
	request, err := s.workflow.GetApprovalRequest(ctx, sess.ID)
	if errors.Is(err, domain.ErrNotFound) {
		return s.sessions.CompleteWorkflowDispatch(ctx, item.SessionID, item.LeaseToken)
	}
	if err != nil {
		return s.retryWorkflowDispatch(ctx, item, "workflow_lookup_unavailable", err)
	}
	return s.cancelWorkflowRequestAndComplete(ctx, item, request, sess)
}

func (s *SessionBrokerService) cancelWorkflowRequestAndComplete(ctx context.Context, item domain.WorkflowDispatch, request *domain.WorkflowApprovalRequest, sess *domain.Session) error {
	if request.Status == domain.WorkflowApprovalPending {
		reason := "session_terminal"
		if !sess.ExpiresAt.After(s.clock()) {
			reason = "session_expired"
		}
		if _, err := s.workflow.CancelApprovalRequest(ctx, request.RequestID, request.Revision, reason); err != nil && !errors.Is(err, domain.ErrConflict) {
			return s.retryWorkflowDispatch(ctx, item, "workflow_cancel_unavailable", err)
		}
	}
	return s.sessions.CompleteWorkflowDispatch(ctx, item.SessionID, item.LeaseToken)
}

func (s *SessionBrokerService) failWorkflowDispatch(ctx context.Context, item domain.WorkflowDispatch, sess *domain.Session, reasonCode string, cause error) error {
	if err := s.emitAudit(ctx, sess.RequestedBy, "session.approval_request_failed", "session", sess.ID, map[string]string{"reason_code": reasonCode}, false); err != nil {
		return s.retryWorkflowDispatch(ctx, item, "audit_unavailable", err)
	}
	denied := *sess
	denied.Status = domain.StatusDenied
	swapped, err := s.sessions.SaveIfStatus(ctx, &denied, domain.StatusPendingApproval)
	if err != nil {
		return s.retryWorkflowDispatch(ctx, item, "session_update_unavailable", err)
	}
	if !swapped {
		current, getErr := s.sessions.Get(ctx, sess.ID)
		if getErr != nil {
			return s.retryWorkflowDispatch(ctx, item, "session_recheck_unavailable", getErr)
		}
		if current.Status == domain.StatusPendingApproval {
			return s.retryWorkflowDispatch(ctx, item, "session_cas_conflict", domain.ErrConflict)
		}
	}
	if err := s.sessions.CompleteWorkflowDispatch(ctx, item.SessionID, item.LeaseToken); err != nil {
		return err
	}
	log.Printf("session-broker: ordinary approval request %s denied closed: %s", sess.ID, reasonCode)
	return nil
}

func (s *SessionBrokerService) retryWorkflowDispatch(ctx context.Context, item domain.WorkflowDispatch, errorCode string, cause error) error {
	delay := time.Duration(1<<min(item.Attempts, 8)) * time.Second
	if delay > 5*time.Minute {
		delay = 5 * time.Minute
	}
	if err := s.sessions.RetryWorkflowDispatch(ctx, item.SessionID, item.LeaseToken, errorCode, s.clock().Add(delay)); err != nil {
		return err
	}
	return nil
}

func workflowDispatchErrorCode(err error, attempts int) string {
	switch {
	case errors.Is(err, domain.ErrWorkflowPermanent):
		return "workflow_refused"
	case errors.Is(err, domain.ErrConflict):
		return "hierarchy_revision_conflict"
	case errors.Is(err, domain.ErrNotFound):
		return "workflow_request_not_found"
	case attempts >= workflowDispatchMaxTries:
		return "workflow_retries_exhausted"
	default:
		return "workflow_unavailable"
	}
}

// decideOrdinaryApproval delegates authority and the immutable approver snapshot
// to Workflow, then applies the resulting decision to the Broker-owned session by CAS.
func (s *SessionBrokerService) decideOrdinaryApproval(ctx context.Context, sess *domain.Session, actorID string, actorRoles []string, approve bool) (*domain.Session, error) {
	if s.workflow == nil {
		return nil, domain.ErrUnavailable
	}
	if actorID == sess.RequestedBy {
		if err := s.emitAudit(ctx, actorID, ordinaryDecisionAction(approve), "session", sess.ID, map[string]string{"ticket": sess.Ticket}, false); err != nil {
			return nil, fmt.Errorf("%w: auditing a self-approval refusal: %v", domain.ErrUnavailable, err)
		}
		return nil, fmt.Errorf("%w: a request cannot be decided by its requester", domain.ErrForbidden)
	}
	now := s.clock()
	if sess.EffectiveStatus(now) != domain.StatusPendingApproval {
		return nil, domain.ErrConflict
	}
	request, err := s.workflow.GetApprovalRequest(ctx, sess.ID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("%w: Workflow has not provisioned this approval yet", domain.ErrConflict)
	}
	if err != nil {
		return nil, fmt.Errorf("%w: reading Workflow approval: %v", domain.ErrUnavailable, err)
	}
	if request.RequestID != sess.ID || request.ResourceType != "session" || request.ResourceID != sess.ID ||
		request.RequesterUserID != sess.RequestedBy || request.AccountID != sess.PrivilegedAccountID ||
		request.TicketReference != sess.Ticket || request.ApproverUserID == "" || request.ApproverUserID == sess.RequestedBy ||
		request.HierarchyRevision == 0 || request.Status != domain.WorkflowApprovalPending ||
		!request.DecisionExpiresAt.Equal(sess.ExpiresAt) {
		return nil, fmt.Errorf("%w: Workflow approval does not match the pending Session Broker request", domain.ErrUnavailable)
	}
	decision := domain.WorkflowApprovalRejected
	if approve {
		decision = domain.WorkflowApprovalApproved
	}
	updatedRequest, err := s.workflow.DecideApprovalRequest(ctx, sess.ID, actorID, actorRoles, request.Revision, decision, "")
	if err != nil {
		if errors.Is(err, domain.ErrForbidden) || errors.Is(err, domain.ErrWorkflowPermanent) {
			if auditErr := s.emitAudit(ctx, actorID, ordinaryDecisionAction(approve), "session", sess.ID, map[string]string{"ticket": sess.Ticket}, false); auditErr != nil {
				return nil, domain.ErrUnavailable
			}
			return nil, fmt.Errorf("%w: Workflow refused the decision", domain.ErrForbidden)
		}
		if errors.Is(err, domain.ErrConflict) {
			return nil, domain.ErrConflict
		}
		return nil, fmt.Errorf("%w: Workflow decision unavailable: %v", domain.ErrUnavailable, err)
	}
	if updatedRequest.Status != decision || updatedRequest.RequestID != sess.ID || updatedRequest.ResourceID != sess.ID ||
		updatedRequest.RequesterUserID != sess.RequestedBy || updatedRequest.AccountID != sess.PrivilegedAccountID ||
		updatedRequest.ApproverUserID != request.ApproverUserID || updatedRequest.HierarchyRevision != request.HierarchyRevision ||
		updatedRequest.DecidedBy != actorID || updatedRequest.DecidedAt == nil {
		return nil, fmt.Errorf("%w: Workflow returned an inconsistent approval decision", domain.ErrUnavailable)
	}
	decidedAt := *updatedRequest.DecidedAt
	if decidedAt.IsZero() || !decidedAt.Before(sess.ExpiresAt) {
		return nil, fmt.Errorf("%w: Workflow decision is outside the pending approval window", domain.ErrUnavailable)
	}
	details := map[string]string{"ticket": sess.Ticket, "workflow_revision": fmt.Sprint(updatedRequest.Revision)}
	if err := s.emitAudit(ctx, actorID, ordinaryDecisionAction(approve), "session", sess.ID, details, true); err != nil {
		return nil, fmt.Errorf("%w: Workflow decided but the session decision could not be audited: %v", domain.ErrUnavailable, err)
	}
	decided := *sess
	decided.DecidedBy, decided.DecidedAt = actorID, &decidedAt
	if approve {
		decided.Status = domain.StatusActive
		decided.ExpiresAt = decidedAt.Add(time.Duration(sess.DurationMinutes) * time.Minute)
	} else {
		decided.Status = domain.StatusDenied
	}
	swapped, err := s.sessions.SaveIfStatus(ctx, &decided, domain.StatusPendingApproval)
	if err != nil {
		return nil, fmt.Errorf("%w: applying Workflow decision to session: %v", domain.ErrUnavailable, err)
	}
	if !swapped {
		current, getErr := s.sessions.Get(ctx, sess.ID)
		if getErr == nil && current.DecidedBy == actorID && current.Status == decided.Status {
			return current, nil
		}
		return nil, domain.ErrConflict
	}
	event := domain.NotifyApprovalRejected
	if approve {
		event = domain.NotifyApprovalApproved
	}
	s.notify(ctx, domain.ApprovalNotification{Event: event, SessionID: decided.ID, AccountID: decided.PrivilegedAccountID,
		RequestedBy: decided.RequestedBy, DecidedBy: actorID,
		Ticket: decided.Ticket, DurationMinutes: decided.DurationMinutes, ExpiresAt: decided.ExpiresAt, At: decidedAt})
	return &decided, nil
}

func ordinaryDecisionAction(approve bool) string {
	if approve {
		return "session.approval_approved"
	}
	return "session.approval_rejected"
}

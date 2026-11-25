package application

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

const (
	SessionApprovalResourcePrefix = "session-approve:account:"
	SessionApprovalAction         = "session:approve"
	maxApprovalTicketLength       = 256
	maxApprovalReasonLength       = 512
	maxPendingApprovalWindow      = 24 * time.Hour
	maxApprovalListWindow         = 100
)

type ApprovalService struct {
	repository domain.ApprovalRepository
	hierarchy  domain.HierarchyRepository
	users      domain.UserDirectory
	authorizer domain.AuthorizationClient
	audit      domain.AuditEmitter
	now        func() time.Time
}

func NewApprovalService(repository domain.ApprovalRepository, hierarchy domain.HierarchyRepository, users domain.UserDirectory, authorizer domain.AuthorizationClient, audit domain.AuditEmitter) *ApprovalService {
	return &ApprovalService{repository: repository, hierarchy: hierarchy, users: users, authorizer: authorizer, audit: audit, now: time.Now}
}

func (s *ApprovalService) WithClock(now func() time.Time) *ApprovalService {
	if now != nil {
		s.now = now
	}
	return s
}

func (s *ApprovalService) clock() time.Time { return s.now().UTC() }

func (s *ApprovalService) CreateApprovalRequest(ctx context.Context, input domain.CreateApprovalInput) (*domain.ApprovalRequest, error) {
	now := s.clock()
	if err := validateCreateApproval(input, now); err != nil {
		return nil, err
	}
	hash := hashApprovalRequest(input)
	if existing, err := s.repository.FindApprovalByIdempotencyKey(ctx, input.IdempotencyKey); err == nil {
		if existing.RequestHash != hash {
			return nil, domain.ErrIdempotencyConflict
		}
		return existing, nil
	} else if !errors.Is(err, domain.ErrNotFound) {
		return nil, fmt.Errorf("%w: approval idempotency lookup unavailable", domain.ErrUnavailable)
	}

	requester, err := s.users.GetAuthorizationContext(ctx, input.RequesterUserID)
	if err != nil {
		return nil, fmt.Errorf("%w: requester identity unavailable", domain.ErrUnavailable)
	}
	if !requester.Exists || !requester.Active {
		if auditErr := s.recordRequestDenied(ctx, input, "requester_inactive_or_missing"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}

	relation, hierarchyRevision, err := s.hierarchy.GetManager(ctx, input.RequesterUserID)
	if errors.Is(err, domain.ErrNotFound) || (err == nil && relation == nil) {
		if auditErr := s.recordRequestDenied(ctx, input, "manager_not_configured"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	if err != nil {
		return nil, fmt.Errorf("%w: approver hierarchy unavailable", domain.ErrUnavailable)
	}
	if relation.ManagerUserID == input.RequesterUserID {
		if auditErr := s.recordRequestDenied(ctx, input, "self_approval"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	approver, err := s.users.GetAuthorizationContext(ctx, relation.ManagerUserID)
	if err != nil {
		return nil, fmt.Errorf("%w: approver identity unavailable", domain.ErrUnavailable)
	}
	if !approver.Exists || !approver.Active {
		if auditErr := s.recordRequestDenied(ctx, input, "manager_inactive_or_missing"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	allowed, _, err := s.authorizer.CheckAccess(ctx, approver.UserID, approver.Roles, SessionApprovalResourcePrefix+input.AccountID, SessionApprovalAction)
	if err != nil {
		return nil, fmt.Errorf("%w: approver authorization unavailable", domain.ErrUnavailable)
	}
	if !allowed {
		if auditErr := s.recordRequestDenied(ctx, input, "manager_not_authorized"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}

	details := map[string]string{"request_id": input.RequestID, "requester_user_id": input.RequesterUserID, "approver_user_id": approver.UserID, "hierarchy_revision": fmt.Sprint(hierarchyRevision)}
	if err := s.audit.EmitEvent(ctx, input.RequesterUserID, "workflow.approver_resolved", "session", input.ResourceID, details, true); err != nil {
		return nil, fmt.Errorf("%w: approver resolution audit unavailable", domain.ErrUnavailable)
	}
	if err := s.audit.EmitEvent(ctx, input.RequesterUserID, "workflow.approval_request_authorized", "session", input.ResourceID, map[string]string{"request_id": input.RequestID, "account_id": input.AccountID, "ticket_reference": input.TicketReference}, true); err != nil {
		return nil, fmt.Errorf("%w: approval request audit unavailable", domain.ErrUnavailable)
	}
	eventID, err := domain.NewID("workflow_audit")
	if err != nil {
		return nil, fmt.Errorf("%w: audit event identifier unavailable", domain.ErrUnavailable)
	}
	event := domain.AuditOutboxEvent{ID: eventID, ActorID: input.RequesterUserID, Action: "workflow.approval_requested", ResourceType: "session", ResourceID: input.ResourceID, Details: details, Success: true}
	request, _, err := s.repository.CreateApprovalRequest(ctx, input, approver.UserID, hierarchyRevision, hash, now, event)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrForbidden) || errors.Is(err, domain.ErrIdempotencyConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: approval request persistence unavailable", domain.ErrUnavailable)
	}
	return request, nil
}

func (s *ApprovalService) GetApprovalRequest(ctx context.Context, requestID string) (*domain.ApprovalRequest, error) {
	if !validUserID(requestID) {
		return nil, domain.ErrInvalid
	}
	request, err := s.repository.GetApprovalRequest(ctx, requestID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: approval request lookup unavailable", domain.ErrUnavailable)
	}
	return request, nil
}

func (s *ApprovalService) ListPendingApprovals(ctx context.Context, actorID string, _ []string, page, pageSize int) (domain.ApprovalPage, error) {
	if !validUserID(actorID) || page < 1 || page > 1_000_000 || pageSize < 1 || pageSize > 100 {
		return domain.ApprovalPage{}, domain.ErrInvalid
	}
	identity, err := s.users.GetAuthorizationContext(ctx, actorID)
	if err != nil {
		return domain.ApprovalPage{}, fmt.Errorf("%w: approver identity unavailable", domain.ErrUnavailable)
	}
	if !identity.Exists || !identity.Active {
		return domain.ApprovalPage{}, domain.ErrForbidden
	}
	pending, err := s.repository.ListPendingApprovals(ctx, actorID, 1, maxApprovalListWindow, s.clock())
	if err != nil {
		return domain.ApprovalPage{}, fmt.Errorf("%w: pending approvals unavailable", domain.ErrUnavailable)
	}
	visible := make([]domain.ApprovalRequest, 0, len(pending.Items))
	for _, request := range pending.Items {
		allowed, _, err := s.authorizer.CheckAccess(ctx, actorID, identity.Roles, SessionApprovalResourcePrefix+request.AccountID, SessionApprovalAction)
		if err != nil {
			return domain.ApprovalPage{}, fmt.Errorf("%w: approval authorization unavailable", domain.ErrUnavailable)
		}
		if allowed {
			visible = append(visible, request)
		}
	}
	start := (page - 1) * pageSize
	if start > len(visible) {
		start = len(visible)
	}
	end := start + pageSize
	if end > len(visible) {
		end = len(visible)
	}
	if err := s.audit.EmitEvent(ctx, actorID, "workflow.approvals.listed", "approval", actorID, map[string]string{"count": fmt.Sprint(len(visible)), "page": fmt.Sprint(page)}, true); err != nil {
		return domain.ApprovalPage{}, fmt.Errorf("%w: approval list audit unavailable", domain.ErrUnavailable)
	}
	return domain.ApprovalPage{Items: append([]domain.ApprovalRequest(nil), visible[start:end]...), Page: page, PageSize: pageSize, TotalItems: len(visible), Truncated: pending.TotalItems > maxApprovalListWindow}, nil
}

func (s *ApprovalService) DecideApprovalRequest(ctx context.Context, requestID, actorID string, _ []string, expectedRevision uint64, decision domain.ApprovalStatus, reason string) (*domain.ApprovalRequest, error) {
	if !validUserID(requestID) || !validUserID(actorID) || (decision != domain.ApprovalApproved && decision != domain.ApprovalRejected) || !validReason(reason) {
		return nil, domain.ErrInvalid
	}
	request, err := s.repository.GetApprovalRequest(ctx, requestID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: approval request lookup unavailable", domain.ErrUnavailable)
	}
	if request.Status == decision && request.DecidedBy == actorID {
		return request, nil
	}
	if request.Status != domain.ApprovalPending {
		return nil, domain.ErrConflict
	}
	now := s.clock()
	if !request.DecisionExpiresAt.After(now) {
		if _, err := s.repository.ExpirePendingApprovals(ctx, now, 100); err != nil {
			return nil, fmt.Errorf("%w: approval expiration unavailable", domain.ErrUnavailable)
		}
		return nil, domain.ErrExpired
	}
	if request.Revision != expectedRevision {
		return nil, domain.ErrConflict
	}
	if actorID != request.ApproverUserID || actorID == request.RequesterUserID {
		if auditErr := s.recordDecisionDenied(ctx, request, actorID, "not_assigned_approver"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	identity, err := s.users.GetAuthorizationContext(ctx, actorID)
	if err != nil {
		return nil, fmt.Errorf("%w: approver identity unavailable", domain.ErrUnavailable)
	}
	if !identity.Exists || !identity.Active {
		if auditErr := s.recordDecisionDenied(ctx, request, actorID, "approver_inactive_or_missing"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	allowed, _, err := s.authorizer.CheckAccess(ctx, actorID, identity.Roles, SessionApprovalResourcePrefix+request.AccountID, SessionApprovalAction)
	if err != nil {
		return nil, fmt.Errorf("%w: approval authorization unavailable", domain.ErrUnavailable)
	}
	if !allowed {
		if auditErr := s.recordDecisionDenied(ctx, request, actorID, "approver_not_authorized"); auditErr != nil {
			return nil, auditErr
		}
		return nil, domain.ErrForbidden
	}
	if err := s.audit.EmitEvent(ctx, actorID, "workflow.approval_decision_authorized", "session", request.ResourceID, map[string]string{"request_id": request.ID, "decision": string(decision)}, true); err != nil {
		return nil, fmt.Errorf("%w: approval decision audit unavailable", domain.ErrUnavailable)
	}
	eventID, err := domain.NewID("workflow_audit")
	if err != nil {
		return nil, fmt.Errorf("%w: audit event identifier unavailable", domain.ErrUnavailable)
	}
	event := domain.AuditOutboxEvent{ID: eventID, ActorID: actorID, Action: "workflow.approval_decided", ResourceType: "session", ResourceID: request.ResourceID, Details: map[string]string{"request_id": request.ID, "decision": string(decision)}, Success: true}
	updated, _, err := s.repository.DecideApprovalRequest(ctx, requestID, expectedRevision, decision, actorID, strings.TrimSpace(reason), now, event)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) || errors.Is(err, domain.ErrExpired) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: approval decision persistence unavailable", domain.ErrUnavailable)
	}
	return updated, nil
}

func (s *ApprovalService) CancelApprovalRequest(ctx context.Context, requestID string, expectedRevision uint64, reasonCode string) (*domain.ApprovalRequest, error) {
	if !validUserID(requestID) || !validReasonCode(reasonCode) {
		return nil, domain.ErrInvalid
	}
	request, err := s.repository.GetApprovalRequest(ctx, requestID)
	if errors.Is(err, domain.ErrNotFound) {
		return nil, err
	}
	if err != nil {
		return nil, fmt.Errorf("%w: approval request lookup unavailable", domain.ErrUnavailable)
	}
	if request.Status == domain.ApprovalCancelled {
		return request, nil
	}
	if request.Status != domain.ApprovalPending {
		return nil, domain.ErrConflict
	}
	if request.Revision != expectedRevision {
		return nil, domain.ErrConflict
	}
	now := s.clock()
	if err := s.audit.EmitEvent(ctx, "", "workflow.approval_request_cancel_authorized", "session", request.ResourceID, map[string]string{"request_id": request.ID, "reason_code": reasonCode}, true); err != nil {
		return nil, fmt.Errorf("%w: approval cancellation audit unavailable", domain.ErrUnavailable)
	}
	eventID, err := domain.NewID("workflow_audit")
	if err != nil {
		return nil, fmt.Errorf("%w: audit event identifier unavailable", domain.ErrUnavailable)
	}
	event := domain.AuditOutboxEvent{ID: eventID, Action: "workflow.approval_request_cancelled", ResourceType: "session", ResourceID: request.ResourceID, Details: map[string]string{"request_id": request.ID, "reason_code": reasonCode}, Success: true}
	updated, _, err := s.repository.CancelApprovalRequest(ctx, requestID, expectedRevision, reasonCode, now, event)
	if err != nil {
		if errors.Is(err, domain.ErrConflict) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: approval cancellation persistence unavailable", domain.ErrUnavailable)
	}
	return updated, nil
}

func (s *ApprovalService) ExpirePending(ctx context.Context) (int, error) {
	return s.repository.ExpirePendingApprovals(ctx, s.clock(), 100)
}

func (s *ApprovalService) recordRequestDenied(ctx context.Context, input domain.CreateApprovalInput, reason string) error {
	if err := s.audit.EmitEvent(ctx, input.RequesterUserID, "workflow.approval_request_denied", "session", input.ResourceID, map[string]string{"request_id": input.RequestID, "reason_code": reason}, false); err != nil {
		return fmt.Errorf("%w: approval refusal audit unavailable", domain.ErrUnavailable)
	}
	return nil
}

func (s *ApprovalService) recordDecisionDenied(ctx context.Context, request *domain.ApprovalRequest, actorID, reason string) error {
	if err := s.audit.EmitEvent(ctx, actorID, "workflow.approval_decision_denied", "session", request.ResourceID, map[string]string{"request_id": request.ID, "reason_code": reason}, false); err != nil {
		return fmt.Errorf("%w: approval refusal audit unavailable", domain.ErrUnavailable)
	}
	return nil
}

func validateCreateApproval(input domain.CreateApprovalInput, now time.Time) error {
	if !validUserID(input.RequestID) || input.RequestID != input.ResourceID || input.IdempotencyKey != input.RequestID || input.ResourceType != "session" || !validUserID(input.RequesterUserID) || !validUserID(input.AccountID) {
		return domain.ErrInvalid
	}
	if len(input.TicketReference) == 0 || len(input.TicketReference) > maxApprovalTicketLength || strings.TrimSpace(input.TicketReference) != input.TicketReference {
		return domain.ErrInvalid
	}
	for _, r := range input.TicketReference {
		if unicode.IsControl(r) {
			return domain.ErrInvalid
		}
	}
	if !input.DecisionExpiresAt.After(now) || input.DecisionExpiresAt.After(now.Add(maxPendingApprovalWindow)) {
		return domain.ErrInvalid
	}
	return nil
}

func hashApprovalRequest(input domain.CreateApprovalInput) [32]byte {
	h := sha256.New()
	write := func(value string) {
		var size [8]byte
		binary.BigEndian.PutUint64(size[:], uint64(len(value)))
		_, _ = h.Write(size[:])
		_, _ = h.Write([]byte(value))
	}
	write(input.ResourceType)
	write(input.ResourceID)
	write(input.RequesterUserID)
	write(input.AccountID)
	write(input.TicketReference)
	write(input.DecisionExpiresAt.UTC().Format(time.RFC3339Nano))
	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

func validReason(reason string) bool {
	if len(reason) > maxApprovalReasonLength || strings.TrimSpace(reason) != reason {
		return false
	}
	for _, r := range reason {
		if unicode.IsControl(r) && r != '\n' && r != '\t' {
			return false
		}
	}
	return true
}

func validReasonCode(reason string) bool {
	if len(reason) == 0 || len(reason) > 64 {
		return false
	}
	for _, r := range reason {
		if !((r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-') {
			return false
		}
	}
	return true
}

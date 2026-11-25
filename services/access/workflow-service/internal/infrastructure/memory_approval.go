package infrastructure

import (
	"context"
	"sort"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

func (s *MemoryStore) FindApprovalByIdempotencyKey(_ context.Context, key string) (*domain.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	id, ok := s.idempotency[key]
	if !ok {
		return nil, domain.ErrNotFound
	}
	request := cloneApproval(s.requests[id])
	return &request, nil
}

func (s *MemoryStore) GetApprovalRequest(_ context.Context, requestID string) (*domain.ApprovalRequest, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[requestID]
	if !ok {
		return nil, domain.ErrNotFound
	}
	copy := cloneApproval(request)
	return &copy, nil
}

func (s *MemoryStore) CreateApprovalRequest(_ context.Context, input domain.CreateApprovalInput, approver string, hierarchyRevision uint64, requestHash [32]byte, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if id, ok := s.idempotency[input.IdempotencyKey]; ok {
		existing := s.requests[id]
		if existing.RequestHash != requestHash {
			return nil, false, domain.ErrIdempotencyConflict
		}
		copy := cloneApproval(existing)
		return &copy, false, nil
	}
	if s.revision != hierarchyRevision {
		return nil, false, domain.ErrConflict
	}
	relation, ok := s.relations[input.RequesterUserID]
	if !ok || relation.ManagerUserID != approver || relation.Revision > hierarchyRevision {
		return nil, false, domain.ErrConflict
	}
	request := domain.ApprovalRequest{
		ID: input.RequestID, ResourceType: input.ResourceType, ResourceID: input.ResourceID,
		RequesterUserID: input.RequesterUserID, AccountID: input.AccountID, TicketReference: input.TicketReference,
		ApproverUserID: approver, HierarchyRevision: hierarchyRevision, Status: domain.ApprovalPending,
		IdempotencyKey: input.IdempotencyKey, RequestHash: requestHash, DecisionExpiresAt: input.DecisionExpiresAt,
		CreatedAt: now, Revision: 1,
	}
	s.requests[request.ID] = request
	s.idempotency[request.IdempotencyKey] = request.ID
	event.DueAt = now
	s.outbox[event.ID] = event
	copy := cloneApproval(request)
	return &copy, true, nil
}

func (s *MemoryStore) ListPendingApprovals(_ context.Context, approver string, page, pageSize int, now time.Time) (domain.ApprovalPage, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	all := make([]domain.ApprovalRequest, 0)
	for _, request := range s.requests {
		if request.ApproverUserID == approver && request.Status == domain.ApprovalPending && request.DecisionExpiresAt.After(now) {
			all = append(all, cloneApproval(request))
		}
	}
	sortApprovalRequests(all)
	total := len(all)
	start := (page - 1) * pageSize
	if start > total {
		start = total
	}
	end := start + pageSize
	if end > total {
		end = total
	}
	return domain.ApprovalPage{Items: append([]domain.ApprovalRequest(nil), all[start:end]...), Page: page, PageSize: pageSize, TotalItems: total}, nil
}

func (s *MemoryStore) DecideApprovalRequest(_ context.Context, requestID string, expected uint64, decision domain.ApprovalStatus, actor, reason string, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[requestID]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	if request.Status == decision && request.DecidedBy == actor && request.DecisionReason == reason {
		copy := cloneApproval(request)
		return &copy, false, nil
	}
	if request.Status != domain.ApprovalPending {
		return nil, false, domain.ErrConflict
	}
	if !request.DecisionExpiresAt.After(now) {
		return nil, false, domain.ErrExpired
	}
	if request.Revision != expected {
		return nil, false, domain.ErrConflict
	}
	decidedAt := now
	request.Status, request.DecidedBy, request.DecidedAt, request.DecisionReason = decision, actor, &decidedAt, reason
	request.Revision++
	s.requests[requestID] = request
	event.DueAt = now
	s.outbox[event.ID] = event
	copy := cloneApproval(request)
	return &copy, true, nil
}

func (s *MemoryStore) CancelApprovalRequest(_ context.Context, requestID string, expected uint64, reason string, now time.Time, event domain.AuditOutboxEvent) (*domain.ApprovalRequest, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	request, ok := s.requests[requestID]
	if !ok {
		return nil, false, domain.ErrNotFound
	}
	if request.Status == domain.ApprovalCancelled && request.DecisionReason == reason {
		copy := cloneApproval(request)
		return &copy, false, nil
	}
	if request.Status != domain.ApprovalPending {
		return nil, false, domain.ErrConflict
	}
	if request.Revision != expected {
		return nil, false, domain.ErrConflict
	}
	request.Status, request.DecisionReason = domain.ApprovalCancelled, reason
	request.Revision++
	s.requests[requestID] = request
	event.DueAt = now
	s.outbox[event.ID] = event
	copy := cloneApproval(request)
	return &copy, true, nil
}

func (s *MemoryStore) ExpirePendingApprovals(_ context.Context, now time.Time, limit int) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	ids := make([]string, 0)
	for id, request := range s.requests {
		if request.Status == domain.ApprovalPending && !request.DecisionExpiresAt.After(now) {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	for _, id := range ids {
		request := s.requests[id]
		request.Status, request.Revision = domain.ApprovalExpired, request.Revision+1
		s.requests[id] = request
		eventID, err := domain.NewID("workflow_audit")
		if err != nil {
			return 0, err
		}
		s.outbox[eventID] = domain.AuditOutboxEvent{ID: eventID, Action: "workflow.approval_request_expired", ResourceType: request.ResourceType, ResourceID: request.ResourceID, Details: map[string]string{"request_id": id, "approver_user_id": request.ApproverUserID}, Success: true, DueAt: now}
	}
	return len(ids), nil
}

func cloneApproval(request domain.ApprovalRequest) domain.ApprovalRequest {
	if request.DecidedAt != nil {
		value := *request.DecidedAt
		request.DecidedAt = &value
	}
	return request
}

func sortApprovalRequests(items []domain.ApprovalRequest) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].CreatedAt.Equal(items[j].CreatedAt) {
			return items[i].ID < items[j].ID
		}
		return items[i].CreatedAt.Before(items[j].CreatedAt)
	})
}

package application_test

import (
	"context"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type fakeWorkflowClient struct {
	mu        sync.Mutex
	allow     bool
	createErr error
	requests  map[string]domain.WorkflowApprovalRequest
	creates   []domain.WorkflowApprovalInput
	now       func() time.Time
}

func newFakeWorkflowClient() *fakeWorkflowClient {
	return &fakeWorkflowClient{allow: true, requests: make(map[string]domain.WorkflowApprovalRequest), now: time.Now}
}

func (f *fakeWorkflowClient) CreateApprovalRequest(_ context.Context, input domain.WorkflowApprovalInput) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.creates = append(f.creates, input)
	if f.createErr != nil {
		return nil, f.createErr
	}
	if !f.allow {
		return nil, domain.ErrWorkflowPermanent
	}
	if existing, ok := f.requests[input.RequestID]; ok {
		copy := existing
		return &copy, nil
	}
	request := domain.WorkflowApprovalRequest{RequestID: input.RequestID, ResourceType: input.ResourceType, ResourceID: input.ResourceID, RequesterUserID: input.RequesterUserID, AccountID: input.AccountID, TicketReference: input.TicketReference, ApproverUserID: approver, HierarchyRevision: 1, Status: domain.WorkflowApprovalPending, DecisionExpiresAt: input.DecisionExpiresAt, CreatedAt: f.now().UTC(), Revision: 1}
	f.requests[input.RequestID] = request
	copy := request
	return &copy, nil
}

func (f *fakeWorkflowClient) GetApprovalRequest(_ context.Context, id string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	request, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	copy := request
	return &copy, nil
}

func (f *fakeWorkflowClient) ListPendingApprovals(_ context.Context, actorID string, _ []string, page, pageSize int) (domain.WorkflowApprovalPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]domain.WorkflowApprovalRequest, 0)
	if f.allow {
		for _, request := range f.requests {
			if request.ApproverUserID == actorID && request.Status == domain.WorkflowApprovalPending {
				items = append(items, request)
			}
		}
	}
	if len(items) > pageSize {
		items = items[:pageSize]
	}
	return domain.WorkflowApprovalPage{Items: items, Page: page, PageSize: pageSize, TotalItems: len(items)}, nil
}

func (f *fakeWorkflowClient) DecideApprovalRequest(_ context.Context, id, actorID string, _ []string, expected uint64, decision domain.WorkflowApprovalStatus, reason string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	request, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if !f.allow {
		return nil, domain.ErrForbidden
	}
	if request.Status == decision && request.DecidedBy == actorID && request.DecisionReason == reason {
		copy := request
		return &copy, nil
	}
	if request.Status != domain.WorkflowApprovalPending || request.Revision != expected {
		return nil, domain.ErrConflict
	}
	if actorID != request.ApproverUserID || actorID == request.RequesterUserID {
		return nil, domain.ErrForbidden
	}
	now := f.now().UTC()
	request.Status, request.DecidedBy, request.DecidedAt, request.DecisionReason = decision, actorID, &now, reason
	request.Revision++
	f.requests[id] = request
	copy := request
	return &copy, nil
}

func (f *fakeWorkflowClient) CancelApprovalRequest(_ context.Context, id string, expected uint64, reason string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	request, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if request.Status == domain.WorkflowApprovalCancelled && request.DecisionReason == reason {
		copy := request
		return &copy, nil
	}
	if request.Status != domain.WorkflowApprovalPending || request.Revision != expected {
		return nil, domain.ErrConflict
	}
	request.Status, request.DecisionReason = domain.WorkflowApprovalCancelled, reason
	request.Revision++
	f.requests[id] = request
	copy := request
	return &copy, nil
}

var _ application.WorkflowApprovalClient = (*fakeWorkflowClient)(nil)

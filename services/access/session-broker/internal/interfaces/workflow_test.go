package interfaces_test

import (
	"context"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// testWorkflow is an isolated Workflow boundary for HTTP tests. Break-glass
// scenarios receive an empty ordinary-approval queue; ordinary requests get a
// stable, preassigned approver so the tests can focus on the Broker HTTP layer.
type testWorkflow struct {
	mu       sync.Mutex
	requests map[string]domain.WorkflowApprovalRequest
}

func newTestWorkflow() *testWorkflow {
	return &testWorkflow{requests: make(map[string]domain.WorkflowApprovalRequest)}
}

func (f *testWorkflow) CreateApprovalRequest(_ context.Context, in domain.WorkflowApprovalInput) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if old, ok := f.requests[in.RequestID]; ok {
		copy := old
		return &copy, nil
	}
	now := time.Now().UTC()
	r := domain.WorkflowApprovalRequest{RequestID: in.RequestID, ResourceType: in.ResourceType, ResourceID: in.ResourceID, RequesterUserID: in.RequesterUserID, AccountID: in.AccountID, TicketReference: in.TicketReference, ApproverUserID: "bob", HierarchyRevision: 1, Status: domain.WorkflowApprovalPending, DecisionExpiresAt: in.DecisionExpiresAt, CreatedAt: now, Revision: 1}
	f.requests[in.RequestID] = r
	copy := r
	return &copy, nil
}

func (f *testWorkflow) GetApprovalRequest(_ context.Context, id string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	copy := r
	return &copy, nil
}

func (f *testWorkflow) ListPendingApprovals(_ context.Context, actorID string, _ []string, page, pageSize int) (domain.WorkflowApprovalPage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	items := make([]domain.WorkflowApprovalRequest, 0)
	for _, r := range f.requests {
		if r.ApproverUserID == actorID && r.Status == domain.WorkflowApprovalPending {
			items = append(items, r)
		}
	}
	if len(items) > pageSize {
		items = items[:pageSize]
	}
	return domain.WorkflowApprovalPage{Items: items, Page: page, PageSize: pageSize, TotalItems: len(items)}, nil
}

func (f *testWorkflow) DecideApprovalRequest(_ context.Context, id, actorID string, _ []string, expected uint64, decision domain.WorkflowApprovalStatus, reason string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if r.Revision != expected || r.Status != domain.WorkflowApprovalPending {
		return nil, domain.ErrConflict
	}
	if r.ApproverUserID != actorID || actorID == r.RequesterUserID {
		return nil, domain.ErrForbidden
	}
	now := time.Now().UTC()
	r.Status, r.DecidedBy, r.DecidedAt, r.DecisionReason = decision, actorID, &now, reason
	r.Revision++
	f.requests[id] = r
	copy := r
	return &copy, nil
}

func (f *testWorkflow) CancelApprovalRequest(_ context.Context, id string, expected uint64, reason string) (*domain.WorkflowApprovalRequest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	r, ok := f.requests[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	if r.Revision != expected || r.Status != domain.WorkflowApprovalPending {
		return nil, domain.ErrConflict
	}
	r.Status, r.DecisionReason = domain.WorkflowApprovalCancelled, reason
	r.Revision++
	f.requests[id] = r
	copy := r
	return &copy, nil
}

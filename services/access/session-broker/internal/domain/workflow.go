package domain

import "time"

type WorkflowApprovalStatus string

const (
	WorkflowApprovalPending   WorkflowApprovalStatus = "pending"
	WorkflowApprovalApproved  WorkflowApprovalStatus = "approved"
	WorkflowApprovalRejected  WorkflowApprovalStatus = "rejected"
	WorkflowApprovalExpired   WorkflowApprovalStatus = "expired"
	WorkflowApprovalCancelled WorkflowApprovalStatus = "cancelled"
)

type WorkflowApprovalInput struct {
	RequestID         string
	ResourceType      string
	ResourceID        string
	RequesterUserID   string
	AccountID         string
	TicketReference   string
	DecisionExpiresAt time.Time
	IdempotencyKey    string
}

type WorkflowApprovalRequest struct {
	RequestID         string
	ResourceType      string
	ResourceID        string
	RequesterUserID   string
	AccountID         string
	TicketReference   string
	ApproverUserID    string
	HierarchyRevision uint64
	Status            WorkflowApprovalStatus
	DecisionExpiresAt time.Time
	CreatedAt         time.Time
	DecidedAt         *time.Time
	DecidedBy         string
	DecisionReason    string
	Revision          uint64
}

type WorkflowApprovalPage struct {
	Items      []WorkflowApprovalRequest
	Page       int
	PageSize   int
	TotalItems int
	Truncated  bool
}

package domain

import (
	"context"
	"time"
)

type ApprovalStatus string

const (
	ApprovalPending   ApprovalStatus = "pending"
	ApprovalApproved  ApprovalStatus = "approved"
	ApprovalRejected  ApprovalStatus = "rejected"
	ApprovalExpired   ApprovalStatus = "expired"
	ApprovalCancelled ApprovalStatus = "cancelled"
)

type ApprovalRequest struct {
	ID                string
	ResourceType      string
	ResourceID        string
	RequesterUserID   string
	AccountID         string
	TicketReference   string
	ApproverUserID    string
	HierarchyRevision uint64
	Status            ApprovalStatus
	IdempotencyKey    string
	RequestHash       [32]byte
	DecisionExpiresAt time.Time
	CreatedAt         time.Time
	DecidedAt         *time.Time
	DecidedBy         string
	DecisionReason    string
	Revision          uint64
}

type CreateApprovalInput struct {
	RequestID         string
	ResourceType      string
	ResourceID        string
	RequesterUserID   string
	AccountID         string
	TicketReference   string
	DecisionExpiresAt time.Time
	IdempotencyKey    string
}

type ApprovalPage struct {
	Items      []ApprovalRequest
	Page       int
	PageSize   int
	TotalItems int
	Truncated  bool
}

type ApprovalRepository interface {
	FindApprovalByIdempotencyKey(ctx context.Context, key string) (*ApprovalRequest, error)
	GetApprovalRequest(ctx context.Context, requestID string) (*ApprovalRequest, error)
	CreateApprovalRequest(ctx context.Context, input CreateApprovalInput, approverUserID string, hierarchyRevision uint64, requestHash [32]byte, now time.Time, event AuditOutboxEvent) (*ApprovalRequest, bool, error)
	ListPendingApprovals(ctx context.Context, approverUserID string, page, pageSize int, now time.Time) (ApprovalPage, error)
	DecideApprovalRequest(ctx context.Context, requestID string, expectedRevision uint64, decision ApprovalStatus, actorUserID, reason string, now time.Time, event AuditOutboxEvent) (*ApprovalRequest, bool, error)
	CancelApprovalRequest(ctx context.Context, requestID string, expectedRevision uint64, reasonCode string, now time.Time, event AuditOutboxEvent) (*ApprovalRequest, bool, error)
	ExpirePendingApprovals(ctx context.Context, now time.Time, limit int) (int, error)
}

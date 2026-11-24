// Package domain owns the approval hierarchy and its persistence contracts.
package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrNotFound            = errors.New("not found")
	ErrConflict            = errors.New("revision conflict")
	ErrCycle               = errors.New("hierarchy cycle")
	ErrInvalid             = errors.New("invalid request")
	ErrForbidden           = errors.New("forbidden")
	ErrUnavailable         = errors.New("dependency unavailable")
	ErrIdempotencyConflict = errors.New("idempotency key conflict")
	ErrExpired             = errors.New("approval request expired")
)

type ManagerRelation struct {
	SubordinateUserID string
	ManagerUserID     string
	Revision          uint64
	CreatedBy         string
	UpdatedBy         string
	CreatedAt         time.Time
	UpdatedAt         time.Time
}

type HierarchyPage struct {
	Items      []ManagerRelation
	Page       int
	PageSize   int
	TotalItems int
	Revision   uint64
}

type HierarchyRepository interface {
	HierarchyRevision(ctx context.Context) (uint64, error)
	GetManager(ctx context.Context, subordinateUserID string) (*ManagerRelation, uint64, error)
	ListHierarchy(ctx context.Context, managerUserID string, page, pageSize int) (HierarchyPage, error)
	SetManager(ctx context.Context, subordinateUserID, managerUserID string, expectedRevision uint64, now time.Time, event AuditOutboxEvent) (*ManagerRelation, bool, error)
	DeleteManager(ctx context.Context, subordinateUserID string, expectedRevision uint64, now time.Time, event AuditOutboxEvent) (uint64, bool, error)
}

type UserAuthorizationContext struct {
	UserID string
	Exists bool
	Active bool
	Roles  []string
}

type UserDirectory interface {
	GetAuthorizationContext(ctx context.Context, userID string) (UserAuthorizationContext, error)
}

type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorUserID string, actorRoles []string, resource, action string) (bool, string, error)
}

type AuditEmitter interface {
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error
}

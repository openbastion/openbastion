package domain

import (
	"context"
	"time"
)

type AuditOutboxEvent struct {
	ID           string
	ActorID      string
	Action       string
	ResourceType string
	ResourceID   string
	Details      map[string]string
	Success      bool
	Attempts     int
	DueAt        time.Time
	LeaseUntil   *time.Time
	LeaseToken   string
}

type AuditOutboxRepository interface {
	ClaimAuditEvents(ctx context.Context, now time.Time, lease time.Duration, limit int) ([]AuditOutboxEvent, error)
	CompleteAuditEvent(ctx context.Context, eventID, leaseToken string) error
	RetryAuditEvent(ctx context.Context, eventID, leaseToken string, dueAt time.Time) error
}

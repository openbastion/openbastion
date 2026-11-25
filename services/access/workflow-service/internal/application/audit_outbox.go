package application

import (
	"context"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

const (
	auditOutboxInterval = 2 * time.Second
	auditOutboxLease    = 30 * time.Second
	auditOutboxBatch    = 50
)

type AuditOutboxDispatcher struct {
	store domain.AuditOutboxRepository
	audit domain.AuditEmitter
	now   func() time.Time
}

func NewAuditOutboxDispatcher(store domain.AuditOutboxRepository, audit domain.AuditEmitter) *AuditOutboxDispatcher {
	return &AuditOutboxDispatcher{store: store, audit: audit, now: time.Now}
}

func (d *AuditOutboxDispatcher) Run(ctx context.Context) {
	ticker := time.NewTicker(auditOutboxInterval)
	defer ticker.Stop()
	for {
		if err := d.Drain(ctx); err != nil && ctx.Err() == nil {
			log.Printf("workflow-service: audit outbox drain failed: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (d *AuditOutboxDispatcher) Drain(ctx context.Context) error {
	now := d.now().UTC()
	events, err := d.store.ClaimAuditEvents(ctx, now, auditOutboxLease, auditOutboxBatch)
	if err != nil {
		return err
	}
	for _, event := range events {
		if err := d.audit.EmitEvent(ctx, event.ActorID, event.Action, event.ResourceType, event.ResourceID, event.Details, event.Success); err != nil {
			delay := time.Duration(1<<min(event.Attempts, 8)) * time.Second
			if delay > 5*time.Minute {
				delay = 5 * time.Minute
			}
			if retryErr := d.store.RetryAuditEvent(ctx, event.ID, event.LeaseToken, now.Add(delay)); retryErr != nil {
				log.Printf("workflow-service: audit outbox retry scheduling failed: %v", retryErr)
			}
			continue
		}
		if err := d.store.CompleteAuditEvent(ctx, event.ID, event.LeaseToken); err != nil {
			log.Printf("workflow-service: audit outbox completion failed: %v", err)
		}
	}
	return nil
}

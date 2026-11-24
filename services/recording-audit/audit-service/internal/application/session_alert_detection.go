package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

var (
	ErrDetectionOutboxUnavailable = errors.New("session alert detection outbox unavailable")
	ErrDetectionAlreadyProcessed  = errors.New("session alert detection already processed")
	// ErrSessionAlertDetectionUnavailable is the stable HTTP-facing alias used by the ingestion handler.
	ErrSessionAlertDetectionUnavailable = ErrDetectionOutboxUnavailable
)

// SessionAlertDetectionStore is the durable worker port. Completion atomically writes
// the alert projection, its audit event, and removes the outbox item.
type SessionAlertDetectionStore interface {
	PendingDetections(context.Context, int) ([]domain.AlertDetectionItem, error)
	DetectionSource(context.Context, string) (*domain.Event, error)
	CompleteDetection(context.Context, domain.AlertDetectionItem, domain.SessionAlert, *domain.Event) error
	DiscardDetection(context.Context, domain.AlertDetectionItem) error
	RetryDetection(context.Context, domain.AlertDetectionItem, string, time.Time) error
}

// ProcessSessionAlertDetections verifies the source chain before interpreting it. Each
// completion is a single store transaction, so a crash cannot leave half an alert.
func (s *AuditService) ProcessSessionAlertDetections(ctx context.Context, limit int) (int, error) {
	store, ok := s.store.(SessionAlertDetectionStore)
	if !ok {
		return 0, ErrDetectionOutboxUnavailable
	}
	if limit < 1 || limit > 100 {
		return 0, fmt.Errorf("detection batch limit must be between 1 and 100")
	}
	items, err := store.PendingDetections(ctx, limit)
	if err != nil || len(items) == 0 {
		return 0, err
	}

	// Verify the full chain once per bounded batch while holding the local append lock.
	// CompleteDetection separately checks the database head under its cross-replica lock.
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.VerifyChain(ctx); err != nil {
		for _, item := range items {
			if retryErr := s.deferDetection(ctx, store, item); retryErr != nil {
				return 0, fmt.Errorf("verify audit chain: %v; persist detection retry: %w", err, retryErr)
			}
		}
		return 0, fmt.Errorf("verify audit chain before session alert detection: %w", err)
	}

	processed := 0
	var deferredErr error
	for _, item := range items {
		if err := ctx.Err(); err != nil {
			return processed, err
		}
		if err := s.processDetection(ctx, store, item); err != nil {
			if retryErr := s.deferDetection(ctx, store, item); retryErr != nil {
				return processed, fmt.Errorf("process session alert detection: %v; persist retry: %w", err, retryErr)
			}
			if deferredErr == nil {
				deferredErr = fmt.Errorf("session alert detection deferred: %w", err)
			}
			continue
		}
		processed++
	}
	return processed, deferredErr
}

func (s *AuditService) deferDetection(ctx context.Context, store SessionAlertDetectionStore, item domain.AlertDetectionItem) error {
	attempt := item.Attempts + 1
	delay := time.Second << min(attempt, 6)
	if delay > time.Minute {
		delay = time.Minute
	}
	return store.RetryDetection(ctx, item, "processing_failed", s.now().Add(delay))
}

func (s *AuditService) processDetection(ctx context.Context, store SessionAlertDetectionStore, item domain.AlertDetectionItem) error {
	source, err := store.DetectionSource(ctx, item.SourceEventID)
	if err != nil {
		return err
	}
	if source == nil || source.ID != item.SourceEventID {
		return fmt.Errorf("detection source event is unavailable")
	}
	rule, matched, err := MatchSessionAlertForVersion(source, item.CatalogVersion)
	if err != nil {
		return err
	}
	if !matched {
		return store.DiscardDetection(ctx, item)
	}
	alertID, err := newAlertID()
	if err != nil {
		return err
	}
	alert := domain.SessionAlert{
		ID: alertID, RuleID: rule.ID, RuleVersion: rule.Version,
		SourceEventID: source.ID, SessionID: source.ResourceID,
		Severity: rule.Severity, Status: domain.AlertStatusUnacknowledged,
		Summary: rule.Summary, DetectedAt: s.now().UTC().Truncate(time.Microsecond),
		CreatedAt: s.now().UTC().Truncate(time.Microsecond), Revision: 1,
	}
	details := map[string]string{
		"alert_id": alert.ID, "rule_id": rule.ID, "rule_version": rule.Version,
		"source_event_id": source.ID, "severity": string(rule.Severity),
	}
	event, err := s.nextEvent(ctx, "audit-service", source.ActorID, "session.alert.detected", "session", source.ResourceID, details, true)
	if err != nil {
		return err
	}
	if err := store.CompleteDetection(ctx, item, alert, event); err != nil {
		if errors.Is(err, domain.ErrAlertDetectionAlreadyProcessed) {
			return nil
		}
		return err
	}
	tip := *event
	s.tip = &tip
	return nil
}

func newAlertID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("generate alert id: %w", err)
	}
	return "alert_" + hex.EncodeToString(raw[:]), nil
}

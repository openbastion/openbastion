package infrastructure

import (
	"bytes"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// InMemoryStore is an in-memory log for local development and tests: append-only, except that
// archived events leave from its start (ADR-0032).
type InMemoryStore struct {
	mu              sync.Mutex
	events          []*domain.Event
	heads           map[string]domain.MetadataHead // ADR-0116 §3
	detectionOutbox map[string]domain.AlertDetectionItem
	sessionAlerts   map[string]domain.SessionAlert
}

func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

func (s *InMemoryStore) Append(ctx context.Context, e *domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
	return nil
}

// AppendWithDetection keeps the source event and its outbox reference atomic in memory.
func (s *InMemoryStore) AppendWithDetection(ctx context.Context, e *domain.Event, catalogVersion string, maxPending int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.detectionOutbox == nil {
		s.detectionOutbox = make(map[string]domain.AlertDetectionItem)
	}
	if len(s.detectionOutbox) >= maxPending {
		return fmt.Errorf("session alert detection outbox is full")
	}
	var lastHash []byte
	if len(s.events) > 0 {
		lastHash = s.events[len(s.events)-1].Hash
	}
	if !bytes.Equal(lastHash, e.PrevHash) {
		return fmt.Errorf("audit chain head moved; event was not appended")
	}
	s.events = append(s.events, e)
	s.detectionOutbox[e.ID] = domain.AlertDetectionItem{SourceEventID: e.ID, CatalogVersion: catalogVersion}
	return nil
}

func (s *InMemoryStore) Last(ctx context.Context) (*domain.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.events) == 0 {
		return nil, nil
	}
	return s.events[len(s.events)-1], nil
}

func (s *InMemoryStore) All(ctx context.Context) ([]*domain.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*domain.Event, len(s.events))
	copy(out, s.events)
	return out, nil
}

// DeleteThrough removes the events from the first through lastID, if they are exactly expected.
func (s *InMemoryStore) DeleteThrough(ctx context.Context, lastID string, expected int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, e := range s.events {
		if e.ID == lastID {
			if i+1 != expected {
				return fmt.Errorf("deleting through %s would remove %d events, not %d: nothing deleted", lastID, i+1, expected)
			}
			s.events = append([]*domain.Event(nil), s.events[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("event %s is not in the chain: nothing deleted", lastID)
}

// AppendAttestation is application.MetadataHeadStore.AppendAttestation, under the store's lock.
func (s *InMemoryStore) AppendAttestation(ctx context.Context, e *domain.Event, head domain.MetadataHead, previous *domain.MetadataHead) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.heads[head.SessionID]
	if ok != (previous != nil) || ok && current.Revision != previous.Revision {
		return fmt.Errorf("the head of session %s moved: nothing written", head.SessionID)
	}
	if s.heads == nil {
		s.heads = map[string]domain.MetadataHead{}
	}
	s.events = append(s.events, e)
	s.heads[head.SessionID] = head
	return nil
}

// MetadataHead is application.MetadataHeadStore.MetadataHead.
func (s *InMemoryStore) MetadataHead(ctx context.Context, sessionID string) (*domain.MetadataHead, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	head, ok := s.heads[sessionID]
	if !ok {
		return nil, nil
	}
	return &head, nil
}

// PendingDetections returns a bounded snapshot of due detection work.
func (s *InMemoryStore) PendingDetections(ctx context.Context, limit int) ([]domain.AlertDetectionItem, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.AlertDetectionItem, 0, len(s.detectionOutbox))
	now := time.Now()
	for _, item := range s.detectionOutbox {
		if !item.NextAttemptAt.After(now) {
			out = append(out, item)
		}
	}
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (s *InMemoryStore) DetectionSource(ctx context.Context, id string) (*domain.Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range s.events {
		if event.ID == id {
			copy := *event
			return &copy, nil
		}
	}
	return nil, nil
}

func (s *InMemoryStore) CompleteDetection(ctx context.Context, item domain.AlertDetectionItem, alert domain.SessionAlert, event *domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.detectionOutbox[item.SourceEventID]; !ok {
		return domain.ErrAlertDetectionAlreadyProcessed
	}
	if s.sessionAlerts == nil {
		s.sessionAlerts = make(map[string]domain.SessionAlert)
	}
	if _, exists := s.sessionAlerts[alert.ID]; exists {
		return fmt.Errorf("session alert id already exists")
	}
	for _, existing := range s.sessionAlerts {
		if existing.SourceEventID == alert.SourceEventID && existing.RuleID == alert.RuleID {
			delete(s.detectionOutbox, item.SourceEventID)
			return domain.ErrAlertDetectionAlreadyProcessed
		}
	}
	var lastHash []byte
	if len(s.events) > 0 {
		lastHash = s.events[len(s.events)-1].Hash
	}
	if !bytes.Equal(lastHash, event.PrevHash) {
		return fmt.Errorf("audit chain head moved during detection")
	}
	s.events = append(s.events, event)
	s.sessionAlerts[alert.ID] = alert
	delete(s.detectionOutbox, item.SourceEventID)
	return nil
}

func (s *InMemoryStore) DiscardDetection(ctx context.Context, item domain.AlertDetectionItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.detectionOutbox, item.SourceEventID)
	return nil
}

func (s *InMemoryStore) RetryDetection(ctx context.Context, item domain.AlertDetectionItem, code string, next time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.detectionOutbox[item.SourceEventID]
	if !ok {
		return nil
	}
	current.Attempts++
	current.NextAttemptAt = next
	s.detectionOutbox[item.SourceEventID] = current
	return nil
}

func (s *InMemoryStore) SessionAlerts() []domain.SessionAlert {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]domain.SessionAlert, 0, len(s.sessionAlerts))
	for _, alert := range s.sessionAlerts {
		out = append(out, alert)
	}
	return out
}

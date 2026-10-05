package infrastructure

import (
	"context"
	"sync"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// InMemoryStore is an append-only in-memory log for local development and
// tests. A PostgreSQL-backed implementation against the partitioned
// audit_events table (doc 06 §3) is the natural next increment.
type InMemoryStore struct {
	mu     sync.Mutex
	events []*domain.Event
}

func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

func (s *InMemoryStore) Append(ctx context.Context, e *domain.Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, e)
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

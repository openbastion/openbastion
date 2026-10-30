package infrastructure

import (
	"context"
	"fmt"
	"sync"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// InMemoryStore is an in-memory log for local development and tests: append-only, except that
// archived events leave from its start (ADR-0032).
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

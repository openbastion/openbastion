package infrastructure

import (
	"context"
	"sync"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type InMemoryStore struct {
	mu       sync.Mutex
	sessions map[string]*domain.Session
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{sessions: map[string]*domain.Session{}}
}

func (s *InMemoryStore) Save(ctx context.Context, sess *domain.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *sess
	s.sessions[sess.ID] = &cp
	return nil
}

func (s *InMemoryStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	cp := *sess
	return &cp, nil
}

// SaveIfStatus is the compare-and-swap of domain.SessionRepository, under the
// store's lock.
func (s *InMemoryStore) SaveIfStatus(ctx context.Context, sess *domain.Session, expected domain.SessionStatus) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	current, ok := s.sessions[sess.ID]
	if !ok || current.Status != expected {
		return false, nil
	}
	cp := *sess
	s.sessions[sess.ID] = &cp
	return true, nil
}

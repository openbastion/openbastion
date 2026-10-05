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

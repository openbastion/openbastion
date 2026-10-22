package infrastructure

import (
	"context"
	"sort"
	"sync"
	"time"

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

// ListPending is domain.SessionRepository.ListPending over the map.
func (s *InMemoryStore) ListPending(ctx context.Context, now time.Time, limit int) ([]*domain.Session, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending []*domain.Session
	for _, sess := range s.sessions {
		if sess.Status == domain.StatusPendingApproval && !sess.ExpiresAt.Before(now) {
			cp := *sess
			pending = append(pending, &cp)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		if !pending[i].ExpiresAt.Equal(pending[j].ExpiresAt) {
			return pending[i].ExpiresAt.Before(pending[j].ExpiresAt)
		}
		return pending[i].ID < pending[j].ID
	})
	if limit >= 0 && len(pending) > limit {
		return pending[:limit], true, nil
	}
	return pending, false, nil
}

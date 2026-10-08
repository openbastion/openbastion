package infrastructure

import (
	"context"
	"sync"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

type InMemoryStore struct {
	mu       sync.Mutex
	policies []*domain.Policy
}

func NewInMemoryStore() *InMemoryStore { return &InMemoryStore{} }

func (s *InMemoryStore) Create(ctx context.Context, p *domain.Policy) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies = append(s.policies, p)
	return nil
}

func (s *InMemoryStore) Count(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.policies), nil
}

func (s *InMemoryStore) ForRoles(ctx context.Context, roles []string) ([]*domain.Policy, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	roleSet := make(map[string]bool, len(roles))
	for _, r := range roles {
		roleSet[r] = true
	}
	var out []*domain.Policy
	for _, p := range s.policies {
		if roleSet[p.Role] {
			out = append(out, p)
		}
	}
	return out, nil
}

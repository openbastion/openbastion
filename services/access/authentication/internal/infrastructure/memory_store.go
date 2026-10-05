package infrastructure

import (
	"context"
	"errors"
	"sync"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

var ErrUserNotFound = errors.New("user not found")
var ErrUsernameTaken = errors.New("username already exists")

type InMemoryStore struct {
	mu         sync.Mutex
	byID       map[string]*domain.User
	byUsername map[string]*domain.User
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: map[string]*domain.User{}, byUsername: map[string]*domain.User{}}
}

func (s *InMemoryStore) Create(ctx context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byUsername[u.Username]; exists {
		return ErrUsernameTaken
	}
	s.byID[u.ID] = u
	s.byUsername[u.Username] = u
	return nil
}

func (s *InMemoryStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byUsername[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

func (s *InMemoryStore) GetByID(ctx context.Context, id string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return u, nil
}

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
	attempts   map[string]domain.LoginAttempt
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{byID: map[string]*domain.User{}, byUsername: map[string]*domain.User{}, attempts: map[string]domain.LoginAttempt{}}
}

func (s *InMemoryStore) Create(ctx context.Context, u *domain.User) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byUsername[u.Username]; exists {
		return ErrUsernameTaken
	}
	if u.ExternalSubject != "" {
		for _, other := range s.byID {
			if other.IdentitySource == u.IdentitySource && other.ExternalSubject == u.ExternalSubject {
				return ErrUsernameTaken
			}
		}
	}
	stored := copyUser(u)
	s.byID[u.ID] = stored
	s.byUsername[u.Username] = stored
	return nil
}

func (s *InMemoryStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byUsername[username]
	if !ok {
		return nil, ErrUserNotFound
	}
	return copyUser(u), nil
}

func (s *InMemoryStore) GetByID(ctx context.Context, id string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return nil, ErrUserNotFound
	}
	return copyUser(u), nil
}

// GetByExternalSubject is domain.UserRepository.GetByExternalSubject.
func (s *InMemoryStore) GetByExternalSubject(ctx context.Context, source, subject string) (*domain.User, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, u := range s.byID {
		if subject != "" && u.IdentitySource == source && u.ExternalSubject == subject {
			return copyUser(u), nil
		}
	}
	return nil, ErrUserNotFound
}

// UpdateIdentity is domain.UserRepository.UpdateIdentity.
func (s *InMemoryStore) UpdateIdentity(ctx context.Context, id, displayName string, roles []string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	u, ok := s.byID[id]
	if !ok {
		return ErrUserNotFound
	}
	u.DisplayName, u.Roles = displayName, append([]string(nil), roles...)
	return nil
}

// SaveAttempt is domain.LoginAttemptRepository.SaveAttempt.
func (s *InMemoryStore) SaveAttempt(ctx context.Context, a domain.LoginAttempt) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.attempts[a.State] = a
	return nil
}

// TakeAttempt is domain.LoginAttemptRepository.TakeAttempt.
func (s *InMemoryStore) TakeAttempt(ctx context.Context, state string) (domain.LoginAttempt, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.attempts[state]
	if !ok {
		return a, domain.ErrAttemptNotFound
	}
	delete(s.attempts, state)
	return a, nil
}

// copyUser: what the store hands out is not what it holds — as with PostgreSQL, changing a
// user read from it changes nothing until it is written back.
func copyUser(u *domain.User) *domain.User {
	cp := *u
	cp.Roles = append([]string(nil), u.Roles...)
	return &cp
}

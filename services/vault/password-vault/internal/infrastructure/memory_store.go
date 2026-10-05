package infrastructure

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// InMemoryStore backs all three repository ports for local development and
// tests. A PostgreSQL-backed implementation following the same interfaces
// and the DDL in OpenBastion_06_Modele_Donnees.md §3 is the natural next
// increment (github.com/lib/pq is reachable from this build environment) —
// nothing in internal/application depends on this file directly.
type InMemoryStore struct {
	mu       sync.Mutex
	accounts map[string]*domain.PrivilegedAccount
	secrets  map[string][]*domain.SecretVersion // accountID -> versions, append-only order
	scopes   map[string]*domain.ScopeGrant
}

func NewInMemoryStore() *InMemoryStore {
	return &InMemoryStore{
		accounts: map[string]*domain.PrivilegedAccount{},
		secrets:  map[string][]*domain.SecretVersion{},
		scopes:   map[string]*domain.ScopeGrant{},
	}
}

func (s *InMemoryStore) Get(ctx context.Context, id string) (*domain.PrivilegedAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return nil, domain.ErrNotFound
	}
	return a, nil
}

func (s *InMemoryStore) Create(ctx context.Context, a *domain.PrivilegedAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a.CreatedAt = time.Now().UTC()
	s.accounts[a.ID] = a
	return nil
}

func (s *InMemoryStore) CurrentVersion(ctx context.Context, accountID string) (*domain.SecretVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.secrets[accountID]
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].SupersededAt == nil {
			return versions[i], nil
		}
	}
	return nil, domain.ErrNotFound
}

func (s *InMemoryStore) AddVersion(ctx context.Context, sv *domain.SecretVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	sv.CreatedAt = time.Now().UTC()
	s.secrets[sv.PrivilegedAccountID] = append(s.secrets[sv.PrivilegedAccountID], sv)
	return nil
}

func (s *InMemoryStore) SupersedeCurrent(ctx context.Context, accountID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().UTC()
	for _, v := range s.secrets[accountID] {
		if v.SupersededAt == nil {
			v.SupersededAt = &now
		}
	}
	return nil
}

func (s *InMemoryStore) Save(ctx context.Context, g *domain.ScopeGrant) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.scopes[g.Token] = g
	return nil
}

func (s *InMemoryStore) ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*domain.ScopeGrant, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	g, ok := s.scopes[token]
	if !ok {
		return nil, errors.New("scope token unknown")
	}
	if g.Consumed {
		return nil, errors.New("scope token already consumed")
	}
	if time.Now().UTC().After(g.ExpiresAt) {
		return nil, errors.New("scope token expired")
	}
	if g.ProxyServiceID != callingProxyID {
		return nil, errors.New("scope token not authorized for calling proxy")
	}
	g.Consumed = true
	return g, nil
}

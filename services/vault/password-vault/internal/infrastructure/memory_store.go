package infrastructure

import (
	"context"
	"errors"
	"sort"
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

// List, like PostgresStore.List, orders by id — the only order a map can
// offer deterministically without an extra field, and good enough for
// the MVP scope this mirrors (doc 05 §2 names no sort order).
func (s *InMemoryStore) List(ctx context.Context, page, pageSize int) ([]*domain.PrivilegedAccount, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := make([]*domain.PrivilegedAccount, 0, len(s.accounts))
	for _, a := range s.accounts {
		if a.DisabledAt == nil {
			active = append(active, a)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].ID < active[j].ID })

	totalItems := len(active)
	start := (page - 1) * pageSize
	if start >= totalItems || start < 0 {
		return []*domain.PrivilegedAccount{}, totalItems, nil
	}
	end := start + pageSize
	if end > totalItems {
		end = totalItems
	}
	return active[start:end], totalItems, nil
}

func (s *InMemoryStore) Disable(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	a.DisabledAt = &now
	return nil
}

// SetHostKey is domain.AccountRepository.SetHostKey.
func (s *InMemoryStore) SetHostKey(ctx context.Context, id, hostKey string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return domain.ErrNotFound
	}
	a.HostKey = hostKey
	return nil
}

// SetReconciliation is domain.AccountRepository.SetReconciliation.
func (s *InMemoryStore) SetReconciliation(ctx context.Context, id, reconciliationID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return domain.ErrNotFound
	}
	a.ReconciliationAccountID = reconciliationID
	return nil
}

func (s *InMemoryStore) MarkRotated(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	a.LastRotatedAt = &now
	return nil
}

func (s *InMemoryStore) CurrentVersion(ctx context.Context, accountID string) (*domain.SecretVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	versions := s.secrets[accountID]
	for i := len(versions) - 1; i >= 0; i-- {
		if versions[i].SupersededAt == nil && !versions[i].Pending {
			return versions[i], nil
		}
	}
	return nil, domain.ErrNotFound
}

// AddPending is domain.SecretRepository.AddPending.
func (s *InMemoryStore) AddPending(ctx context.Context, sv *domain.SecretVersion) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.secrets[sv.PrivilegedAccountID] {
		if v.Pending {
			return domain.ErrRotationInProgress
		}
	}
	cp := *sv
	cp.Pending, cp.CreatedAt = true, time.Now().UTC()
	s.secrets[sv.PrivilegedAccountID] = append(s.secrets[sv.PrivilegedAccountID], &cp)
	return nil
}

// PendingVersion is domain.SecretRepository.PendingVersion.
func (s *InMemoryStore) PendingVersion(ctx context.Context, accountID string) (*domain.SecretVersion, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, v := range s.secrets[accountID] {
		if v.Pending {
			cp := *v
			return &cp, nil
		}
	}
	return nil, nil
}

// PromotePending is domain.SecretRepository.PromotePending, under the store's lock.
func (s *InMemoryStore) PromotePending(ctx context.Context, accountID string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var pending *domain.SecretVersion
	for _, v := range s.secrets[accountID] {
		if v.Pending && v.Version == version {
			pending = v
		}
	}
	if pending == nil {
		return domain.ErrNotFound
	}
	now := time.Now().UTC()
	for _, v := range s.secrets[accountID] {
		if !v.Pending && v.SupersededAt == nil {
			v.SupersededAt = &now
		}
	}
	pending.Pending = false
	return nil
}

// DiscardPending is domain.SecretRepository.DiscardPending.
func (s *InMemoryStore) DiscardPending(ctx context.Context, accountID string, version int) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	kept := s.secrets[accountID][:0]
	for _, v := range s.secrets[accountID] {
		if !(v.Pending && v.Version == version) {
			kept = append(kept, v)
		}
	}
	s.secrets[accountID] = kept
	return nil
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
		if v.SupersededAt == nil && !v.Pending {
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

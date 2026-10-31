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
// and the DDL in docs/architecture/data-architecture.md §3 is the natural next
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
	return copyAccount(a), nil
}

// copyAccount is what a caller gets: its own copy, as from a database, never the store's
// record — which another goroutine (the rotation sweep, ADR-0040) may change meanwhile.
func copyAccount(a *domain.PrivilegedAccount) *domain.PrivilegedAccount {
	cp := *a
	return &cp
}

func (s *InMemoryStore) Create(ctx context.Context, a *domain.PrivilegedAccount) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	// The same uniqueness as the database (ADR-0043): this store used to overwrite.
	for _, other := range s.accounts {
		if other.ID == a.ID || (other.TargetHost == a.TargetHost && other.Name == a.Name) {
			return domain.ErrAlreadyExists
		}
	}
	a.CreatedAt = time.Now().UTC()
	s.accounts[a.ID] = copyAccount(a)
	return nil
}

// List, like PostgresStore.List, orders by id — the only order a map can
// offer deterministically without an extra field, and good enough for
// the MVP scope this mirrors (docs/api/rest/openapi.yaml names no sort order).
func (s *InMemoryStore) List(ctx context.Context, page, pageSize int) ([]*domain.PrivilegedAccount, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	active := make([]*domain.PrivilegedAccount, 0, len(s.accounts))
	for _, a := range s.accounts {
		if a.DisabledAt == nil {
			active = append(active, copyAccount(a))
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
	a.RotationFailures = 0
	a.RotationOwedSince = nil
	return nil
}

// RecordRotationFailure is domain.AccountRepository.RecordRotationFailure.
func (s *InMemoryStore) RecordRotationFailure(ctx context.Context, id string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return 0, domain.ErrNotFound
	}
	a.RotationFailures++
	return a.RotationFailures, nil
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

// memoryDue is PostgresStore's condition (ADR-0040, ADR-0044), on a record of this store.
func memoryDue(a *domain.PrivilegedAccount, now time.Time, retryAfter time.Duration, scheduled bool) (bool, time.Time) {
	due, at := a.RotationDue(now, scheduled)
	if !due {
		return false, at
	}
	return a.RotationAttemptedAt == nil || !a.RotationAttemptedAt.After(now.Add(-retryAfter)), at
}

// ListDueForRotation is domain.AccountRepository.ListDueForRotation.
func (s *InMemoryStore) ListDueForRotation(ctx context.Context, now time.Time, retryAfter time.Duration, limit int, scheduled bool) ([]*domain.PrivilegedAccount, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	type waiting struct {
		a  *domain.PrivilegedAccount
		at time.Time
	}
	var due []waiting
	for _, a := range s.accounts {
		if ok, at := memoryDue(a, now, retryAfter, scheduled); ok {
			due = append(due, waiting{copyAccount(a), at})
		}
	}
	sort.Slice(due, func(i, j int) bool {
		if !due[i].at.Equal(due[j].at) {
			return due[i].at.Before(due[j].at)
		}
		return due[i].a.ID < due[j].a.ID
	})
	if len(due) > limit {
		due = due[:limit]
	}
	out := make([]*domain.PrivilegedAccount, len(due))
	for i, d := range due {
		out[i] = d.a
	}
	return out, nil
}

// MarkRotationOwed is domain.AccountRepository.MarkRotationOwed.
func (s *InMemoryStore) MarkRotationOwed(ctx context.Context, id string, at time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if !ok {
		return domain.ErrNotFound
	}
	if a.RotationOwedSince == nil {
		// A new debt is a reason to try now: the delay after an attempt is for failures.
		a.RotationAttemptedAt = nil
	}
	if a.RotationOwedSince == nil || at.Before(*a.RotationOwedSince) {
		since := at
		a.RotationOwedSince = &since
	}
	return nil
}

// ClaimRotation is domain.AccountRepository.ClaimRotation.
func (s *InMemoryStore) ClaimRotation(ctx context.Context, id string, now time.Time, retryAfter time.Duration) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.accounts[id]
	if due, _ := memoryDue(a, now, retryAfter, true); !ok || !due {
		return false, nil
	}
	at := now
	a.RotationAttemptedAt = &at
	return true, nil
}

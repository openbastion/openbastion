package infrastructure

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type memoryActionGrant struct {
	grant    domain.MFAActionGrant
	consumed bool
}

// SaveActionGrant stores only the grant hash and its immutable binding context.
func (s *InMemoryStore) SaveActionGrant(_ context.Context, grant domain.MFAActionGrant) error {
	if err := grant.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(grant.Hash)
	if _, exists := s.mfa.actionGrants[key]; exists {
		return domain.ErrMFAActionGrantExists
	}
	copy := grant
	copy.Hash = append([]byte(nil), grant.Hash...)
	s.mfa.actionGrants[key] = memoryActionGrant{grant: copy}
	return nil
}

// ConsumeActionGrant is a compare-and-swap under the store mutex. A grant is
// accepted only once, before expiry, and for the exact context that was issued.
func (s *InMemoryStore) ConsumeActionGrant(_ context.Context, hash []byte, expected domain.MFAActionGrantBinding, now time.Time) (bool, error) {
	if len(hash) != 32 || expected.Validate() != nil {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	key := hex.EncodeToString(hash)
	stored, ok := s.mfa.actionGrants[key]
	if !ok || stored.consumed || !now.Before(stored.grant.ExpiresAt) {
		return false, nil
	}
	if stored.grant.UserID != expected.UserID ||
		stored.grant.SessionID != expected.SessionID ||
		stored.grant.AccountID != expected.AccountID ||
		stored.grant.Protocol != expected.Protocol ||
		stored.grant.Action != expected.Action {
		return false, nil
	}
	stored.consumed = true
	s.mfa.actionGrants[key] = stored
	return true, nil
}

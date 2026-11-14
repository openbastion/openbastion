package infrastructure

import (
	"context"
	"encoding/hex"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type memoryActionChallenge struct {
	challenge domain.MFAActionChallenge
}

// SaveActionChallenge stores the digest and a copy of its immutable action context.
func (s *InMemoryStore) SaveActionChallenge(_ context.Context, challenge domain.MFAActionChallenge) error {
	if err := challenge.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(challenge.Hash)
	if _, exists := s.mfa.actionChallenges[key]; exists {
		return domain.ErrMFAActionGrantExists
	}
	copy := challenge
	copy.Hash = append([]byte(nil), challenge.Hash...)
	copy.Factors = append([]string(nil), challenge.Factors...)
	copy.WebAuthnSession = append([]byte(nil), challenge.WebAuthnSession...)
	s.mfa.actionChallenges[key] = memoryActionChallenge{challenge: copy}
	return nil
}

func (s *InMemoryStore) GetActionChallenge(_ context.Context, hash []byte) (domain.MFAActionChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	challenge, ok := s.mfa.actionChallenges[hex.EncodeToString(hash)]
	if !ok {
		return domain.MFAActionChallenge{}, domain.ErrChallengeNotFound
	}
	out := challenge.challenge
	out.Hash = append([]byte(nil), out.Hash...)
	out.Factors = append([]string(nil), out.Factors...)
	out.WebAuthnSession = append([]byte(nil), out.WebAuthnSession...)
	return out, nil
}

func (s *InMemoryStore) FailActionChallenge(_ context.Context, hash []byte, max int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(hash)
	stored, ok := s.mfa.actionChallenges[key]
	if !ok {
		return true, nil
	}
	stored.challenge.Attempts++
	if stored.challenge.Attempts >= max {
		delete(s.mfa.actionChallenges, key)
		return true, nil
	}
	s.mfa.actionChallenges[key] = stored
	return false, nil
}

// ConsumeActionChallenge is a one-winner compare-and-swap. Expired challenges are
// deleted as they are refused; concurrent verifiers cannot mint two grants.
func (s *InMemoryStore) ConsumeActionChallenge(_ context.Context, hash []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := hex.EncodeToString(hash)
	stored, ok := s.mfa.actionChallenges[key]
	if !ok {
		return false, nil
	}
	delete(s.mfa.actionChallenges, key)
	return now.Before(stored.challenge.ExpiresAt), nil
}

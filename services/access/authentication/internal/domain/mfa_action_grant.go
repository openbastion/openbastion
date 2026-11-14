package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidMFAActionGrant = errors.New("invalid MFA action grant")
	ErrMFAActionGrantExists  = errors.New("MFA action grant already exists")
)

// MFAActionGrant is a one-time proof that a user completed a fresh second factor
// for one exact privileged-session action. Hash contains SHA-256 of the opaque
// random grant, never the grant itself.
type MFAActionGrant struct {
	Hash      []byte
	UserID    string
	SessionID string
	AccountID string
	Protocol  string
	Action    string
	ExpiresAt time.Time
}

// MFAActionGrantBinding is the expected context supplied when a grant is consumed.
// It deliberately has no expiry field: expiry is authoritative in the store.
type MFAActionGrantBinding struct {
	UserID    string
	SessionID string
	AccountID string
	Protocol  string
	Action    string
}

func (b MFAActionGrantBinding) Validate() error {
	if !validGrantField(b.UserID) || !validGrantField(b.SessionID) || !validGrantField(b.AccountID) {
		return ErrInvalidMFAActionGrant
	}
	switch b.Protocol {
	case "ssh", "vnc", "rdp":
	default:
		return ErrInvalidMFAActionGrant
	}
	switch b.Action {
	case "secret:inject", "secret:paste":
	default:
		return ErrInvalidMFAActionGrant
	}
	return nil
}

// Validate checks the stored grant, including the SHA-256 digest and expiration.
func (g MFAActionGrant) Validate() error {
	if len(g.Hash) != 32 || g.ExpiresAt.IsZero() {
		return ErrInvalidMFAActionGrant
	}
	return (MFAActionGrantBinding{
		UserID: g.UserID, SessionID: g.SessionID, AccountID: g.AccountID,
		Protocol: g.Protocol, Action: g.Action,
	}).Validate()
}

func validGrantField(value string) bool {
	return value != "" && len(value) <= 256
}

// MFAActionGrantRepository stores only grant hashes. ConsumeActionGrant must be
// atomic across all service replicas and must return true for at most one caller.
type MFAActionGrantRepository interface {
	SaveActionGrant(ctx context.Context, grant MFAActionGrant) error
	ConsumeActionGrant(ctx context.Context, hash []byte, expected MFAActionGrantBinding, now time.Time) (bool, error)
}

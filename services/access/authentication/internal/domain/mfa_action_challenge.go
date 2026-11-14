package domain

import (
	"context"
	"time"
)

// MFAActionChallenge is a short-lived second-factor ceremony bound to one exact
// privileged-session action. Only its SHA-256 digest is stored.
type MFAActionChallenge struct {
	Hash            []byte
	Binding         MFAActionGrantBinding
	Factors         []string
	WebAuthnSession []byte
	Attempts        int
	ExpiresAt       time.Time
}

// MFAActionRepository stores action challenges and one-time action grants.
// Challenge consumption and grant consumption must be atomic across replicas.
type MFAActionRepository interface {
	MFAActionGrantRepository
	SaveActionChallenge(ctx context.Context, challenge MFAActionChallenge) error
	GetActionChallenge(ctx context.Context, hash []byte) (MFAActionChallenge, error)
	FailActionChallenge(ctx context.Context, hash []byte, max int) (bool, error)
	ConsumeActionChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error)
}

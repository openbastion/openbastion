package application

// Scheduled rotations (ADR-0040): the Vault sweeps for scheduled accounts that are due, takes
// each by compare-and-swap, and rotates it as a system action, by the path of ADR-0037.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

const (
	// MaxRotationIntervalDays bounds the interval of a scheduled account.
	MaxRotationIntervalDays = 365
	// RotationRetryAfter is how long an account that was tried — rotated or not — is left
	// alone: a target that is down is not tried at every sweep, nor written to the audit.
	RotationRetryAfter = time.Hour
	// RotationsPerSweep bounds one sweep: rotations reach targets one at a time.
	RotationsPerSweep = 20
)

// ErrBadRotationInterval: a scheduled account without an interval in 1..365 days, or an
// interval on an account no schedule runs.
var ErrBadRotationInterval = errors.New("a scheduled account needs rotationIntervalDays between 1 and 365, and only a scheduled account takes one")

func checkSchedule(policy domain.RotationPolicy, days int) error {
	if policy == domain.RotationScheduled {
		if days < 1 || days > MaxRotationIntervalDays {
			return ErrBadRotationInterval
		}
		return nil
	}
	if days != 0 {
		return ErrBadRotationInterval
	}
	return nil
}

// WithClock sets the clock of the scheduled rotations (tests).
func (s *VaultService) WithClock(now func() time.Time) *VaultService {
	s.now = now
	return s
}

// SweepResult is what one sweep did.
type SweepResult struct {
	Rotated int
	Failed  int
}

// RotateDue rotates the scheduled accounts that are due, at most RotationsPerSweep of them,
// the longest overdue first. Each is taken first (ClaimRotation): of two Vaults, one rotates
// it. A failure is logged and left for RotationRetryAfter; it does not stop the sweep.
func (s *VaultService) RotateDue(ctx context.Context) (SweepResult, error) {
	var res SweepResult
	if s.targets == nil || s.audit == nil {
		return res, ErrRotationOff
	}
	now := s.now()
	due, err := s.accounts.ListDueForRotation(ctx, now, RotationRetryAfter, RotationsPerSweep)
	if err != nil {
		return res, fmt.Errorf("listing the accounts due for rotation: %w", err)
	}
	for _, a := range due {
		if ctx.Err() != nil {
			return res, ctx.Err()
		}
		taken, err := s.accounts.ClaimRotation(ctx, a.ID, now, RotationRetryAfter)
		if err != nil {
			return res, fmt.Errorf("taking account %s for rotation: %w", a.ID, err)
		}
		if !taken {
			continue // another Vault has it, or it is no longer due
		}
		if err := s.rotate(ctx, "", a.ID, nil); err != nil {
			res.Failed++
			log.Printf("password-vault: scheduled rotation of account %s failed, tried again in %s: %v", a.ID, RotationRetryAfter, err)
			continue
		}
		res.Rotated++
	}
	return res, nil
}

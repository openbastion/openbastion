package application

// Scheduled rotations (ADR-0040): the Vault sweeps for scheduled accounts that are due, takes
// each by compare-and-swap, and rotates it as a system action, by the path of ADR-0037.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strconv"
	"strings"
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
	// DefaultRotationAlertAfter is how many scheduled rotations of an account fail in a row
	// before vault.rotation_overdue is written (ADR-0041), and again every as many after.
	DefaultRotationAlertAfter = 3
	MaxRotationAlertAfter     = 100
)

// RotationWindow is the time of day, in UTC, when scheduled rotations may run (ADR-0041):
// from start to end, in minutes after midnight; end before start crosses midnight.
type RotationWindow struct {
	start, end int
	set        bool
}

// ParseRotationWindow reads "HH:MM-HH:MM" (UTC). Empty: any time. A window that does not
// read, or lasts no time, is an error — the Vault refuses to start on it.
func ParseRotationWindow(s string) (RotationWindow, error) {
	if s == "" {
		return RotationWindow{}, nil
	}
	from, to, ok := strings.Cut(s, "-")
	start, err1 := minuteOfDay(from)
	end, err2 := minuteOfDay(to)
	if !ok || err1 != nil || err2 != nil {
		return RotationWindow{}, fmt.Errorf("a rotation window is HH:MM-HH:MM in UTC, got %q", s)
	}
	if start == end {
		return RotationWindow{}, fmt.Errorf("the rotation window %q lasts no time", s)
	}
	return RotationWindow{start: start, end: end, set: true}, nil
}

func minuteOfDay(s string) (int, error) {
	h, m, ok := strings.Cut(strings.TrimSpace(s), ":")
	hh, err1 := strconv.Atoi(h)
	mm, err2 := strconv.Atoi(m)
	if !ok || err1 != nil || err2 != nil || len(h) != 2 || len(m) != 2 || hh < 0 || hh > 23 || mm < 0 || mm > 59 {
		return 0, fmt.Errorf("not a time of day: %q", s)
	}
	return hh*60 + mm, nil
}

// Contains says whether t falls in the window; an unset window contains every moment.
func (w RotationWindow) Contains(t time.Time) bool {
	if !w.set {
		return true
	}
	u := t.UTC()
	m := u.Hour()*60 + u.Minute()
	if w.start < w.end {
		return m >= w.start && m < w.end
	}
	return m >= w.start || m < w.end // across midnight
}

// String is the window as configured, or "any time".
func (w RotationWindow) String() string {
	if !w.set {
		return "any time"
	}
	return fmt.Sprintf("%02d:%02d-%02d:%02d UTC", w.start/60, w.start%60, w.end/60, w.end%60)
}

// WithRotationSchedule sets the window of the scheduled rotations and how many failures in a
// row raise an alert (ADR-0041). alertAfter outside 1..MaxRotationAlertAfter is an error.
func (s *VaultService) WithRotationSchedule(window RotationWindow, alertAfter int) (*VaultService, error) {
	if alertAfter < 1 || alertAfter > MaxRotationAlertAfter {
		return nil, fmt.Errorf("the alert threshold of failed rotations is between 1 and %d, got %d", MaxRotationAlertAfter, alertAfter)
	}
	s.window, s.alertAfter = window, alertAfter
	return s, nil
}

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
	// OutsideWindow: the sweep took nothing, the time of day being outside the window.
	OutsideWindow bool
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
	// The window holds the scheduled rotations only: a rotation owed after use (ADR-0044) — a
	// secret a human has just used — does not wait for the night.
	scheduled := s.window.Contains(now)
	res.OutsideWindow = !scheduled
	due, err := s.accounts.ListDueForRotation(ctx, now, RotationRetryAfter, RotationsPerSweep, scheduled)
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
			s.countFailure(ctx, a.ID)
			continue
		}
		res.Rotated++
	}
	return res, nil
}

// countFailure counts a failed scheduled rotation and, at every alertAfter-th in a row, writes
// vault.rotation_overdue to the audit (ADR-0041): the secret is getting older than its policy.
// Best effort — the rotation has failed whatever the audit answers; a lost alert is written
// again alertAfter failures later.
func (s *VaultService) countFailure(ctx context.Context, accountID string) {
	n, err := s.accounts.RecordRotationFailure(ctx, accountID)
	if err != nil {
		log.Printf("password-vault: counting the failed rotation of account %s: %v", accountID, err)
		return
	}
	alertAfter := s.alertAfter
	if alertAfter == 0 {
		alertAfter = DefaultRotationAlertAfter
	}
	if n%alertAfter != 0 {
		return
	}
	log.Printf("password-vault: ALERT the scheduled rotation of account %s has failed %d time(s) in a row", accountID, n)
	if err := s.audit.EmitEvent(ctx, "", "vault.rotation_overdue", "account", accountID, false); err != nil {
		log.Printf("password-vault: the alert for account %s could not be written to the audit (written again in %d failures): %v", accountID, alertAfter, err)
	}
}

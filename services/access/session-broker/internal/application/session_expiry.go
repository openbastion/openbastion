package application

// Expiring the sessions and requests past their end, and writing the expiry to the trail
// (ADR-0034).

import (
	"context"
	"sort"
	"sync"
	"time"
)

// ExpirySweepBatch is how many sessions one step of a sweep expires or writes at most.
const ExpirySweepBatch = 100

// ExpiryAuditGrace is how long an expiry not yet in the trail is left to the replica that made
// it before any sweep takes it over — what a replica stopped before writing leaves behind. It
// is longer than a sweep may last (ExpirySweepTimeout), so that what a replica is writing at
// that very moment is not written twice. A replica retries its own at its next sweep.
const ExpiryAuditGrace = 30 * time.Second

// ExpirySweepTimeout bounds one sweep: an audit that hangs does not hold the sweep for ever.
const ExpirySweepTimeout = 10 * time.Second

// unwrittenExpiries are the sessions this process expired and could not yet write to the
// trail: retried at its next sweep, without waiting for ExpiryAuditGrace.
type unwrittenExpiries struct {
	mu  sync.Mutex
	ids map[string]bool
}

func (u *unwrittenExpiries) add(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	if u.ids == nil {
		u.ids = map[string]bool{}
	}
	u.ids[id] = true
}

func (u *unwrittenExpiries) done(id string) {
	u.mu.Lock()
	defer u.mu.Unlock()
	delete(u.ids, id)
}

func (u *unwrittenExpiries) list() []string {
	u.mu.Lock()
	defer u.mu.Unlock()
	out := make([]string, 0, len(u.ids))
	for id := range u.ids {
		out = append(out, id)
	}
	sort.Strings(out)
	return out
}

// ExpireDue marks expired every active session and pending request past its end, writes each
// expiry to the audit trail — `session.expire`, a system action (no actor) — and writes the
// expiries an earlier sweep could not. It returns how many sessions it expired and how many
// expiries it wrote. It stops at the first expiry the audit refuses: what is expired stays
// expired, its event waits for the next sweep — written at least once, never lost.
func (s *SessionBrokerService) ExpireDue(ctx context.Context) (expired, written int, err error) {
	ctx, cancel := context.WithTimeout(ctx, ExpirySweepTimeout)
	defer cancel()
	now := s.clock()
	for _, id := range s.unwritten.list() {
		if err := s.writeExpiry(ctx, id); err != nil {
			return expired, written, err
		}
		written++
	}
	for {
		due, err := s.sessions.ExpireDue(ctx, now, ExpirySweepBatch)
		if err != nil {
			return expired, written, err
		}
		expired += len(due)
		for _, sess := range due {
			s.unwritten.add(sess.ID)
		}
		for _, sess := range due {
			if err := s.writeExpiry(ctx, sess.ID); err != nil {
				return expired, written, err
			}
			written++
		}
		if len(due) < ExpirySweepBatch {
			break
		}
	}
	for {
		late, err := s.sessions.ExpiriesToAudit(ctx, now.Add(-ExpiryAuditGrace), ExpirySweepBatch)
		if err != nil {
			return expired, written, err
		}
		for _, sess := range late {
			if err := s.writeExpiry(ctx, sess.ID); err != nil {
				return expired, written, err
			}
			written++
		}
		if len(late) < ExpirySweepBatch {
			return expired, written, nil
		}
	}
}

func (s *SessionBrokerService) writeExpiry(ctx context.Context, id string) error {
	if err := s.audit.EmitEvent(ctx, "", "session.expire", "session", id, true); err != nil {
		return err
	}
	if err := s.sessions.MarkExpiryAudited(ctx, id); err != nil {
		return err
	}
	s.unwritten.done(id)
	return nil
}

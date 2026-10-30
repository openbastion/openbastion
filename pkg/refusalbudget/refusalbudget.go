// Package refusalbudget decides how many of the refusals of one identity are written to
// the audit trail (ADR-0020, ADR-0024). A refusal is always a refusal — the answer never
// depends on this — but what a refusal writes must be bounded, or being refused would be a
// way for any holder of a token to write into the signed trail as often as it likes.
//
// It is shared by the Session Broker (refused reads of a session, ADR-0020) and the Command
// Recorder (refused reads of a recording, ADR-0024). Standard library only.
package refusalbudget

import (
	"math"
	"sync"
	"time"
)

// What the refusals of one user may write to the audit: a burst, then a steady rate. The
// defaults are the strict ones — and there is no "unlimited" and no "off": a service that
// reads these from its environment stops on a value outside the bounds.
const (
	DefaultBurst         = 10
	DefaultRatePerMinute = 6
	MaxBurst             = 1000
	MaxRatePerMinute     = 600
)

// Budget is a token bucket per key, the same model as the Gateway's limiter (ADR-0014): a
// key may have `burst` refusals written at once, and then one more every minute/perMinute.
// It is not the Gateway's: that one answers a retry delay, not a yes or a no. The key is the
// verified identity the Gateway named — a finite set of authenticated users, not of
// addresses — and a bucket that has had time to fill again is dropped, so what is held is
// what has refused something recently. Per process: with N replicas, N times the budget.
type Budget struct {
	mu        sync.Mutex
	buckets   map[string]*refusalBucket
	capacity  float64
	refill    time.Duration // time to accumulate one token
	now       func() time.Time
	nextSweep time.Time
}

type refusalBucket struct {
	tokens     float64
	lastRefill time.Time
	spent      bool // the last refusal of this key was not written
}

// New is a budget of `burst` refusals, with `perMinute` given back every
// minute. A value that is not positive gets the default: a budget built by hand is the
// strict one.
func New(burst, perMinute int) *Budget {
	if burst <= 0 {
		burst = DefaultBurst
	}
	if perMinute <= 0 {
		perMinute = DefaultRatePerMinute
	}
	return &Budget{
		buckets: map[string]*refusalBucket{}, capacity: float64(burst),
		refill: time.Minute / time.Duration(perMinute), now: time.Now,
	}
}

// WithClock replaces the clock; for tests.
func (b *Budget) WithClock(now func() time.Time) *Budget {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	return b
}

// Burst and RatePerMinute say what the budget really is, for the line a service writes
// at start-up.
func (b *Budget) Burst() int { return int(b.capacity) }
func (b *Budget) RatePerMinute() int {
	return int(math.Round(float64(time.Minute) / float64(b.refill)))
}

// Tracked is how many identities the budget holds a bucket for: what the memory is made of.
func (b *Budget) Tracked() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}

// Take spends one token of key. write says whether this refusal is written to the audit;
// firstUnwritten is true for the first one that is not since this key last had one written
// — what a log line is for, instead of one per refusal.
func (b *Budget) Take(key string) (write, firstUnwritten bool) {
	b.mu.Lock()
	defer b.mu.Unlock()

	now := b.now()
	b.sweep(now)
	bk, ok := b.buckets[key]
	if !ok {
		bk = &refusalBucket{tokens: b.capacity, lastRefill: now}
		b.buckets[key] = bk
	}
	// A clock that goes back gives nothing and takes nothing: the reference moves forward
	// only, so that going back and forth is not a way to have tokens come back.
	if elapsed := now.Sub(bk.lastRefill); elapsed > 0 {
		bk.tokens += elapsed.Seconds() / b.refill.Seconds()
		if bk.tokens > b.capacity {
			bk.tokens = b.capacity
		}
		bk.lastRefill = now
	}

	if bk.tokens < 1 {
		first := !bk.spent
		bk.spent = true
		return false, first
	}
	bk.tokens--
	bk.spent = false
	return true, false
}

// sweep drops the buckets that have been idle long enough to be full again: a full bucket
// decides exactly as one that never existed, so nothing a refusal writes changes; what
// stops is the map growing for as long as the process lives. The margin is there so that
// floating-point rounding can never make a dropped bucket differ from a new one.
func (b *Budget) sweep(now time.Time) {
	if now.Before(b.nextSweep) {
		return
	}
	full := time.Duration(b.capacity * float64(b.refill))
	evictAfter := full + full/10 + time.Millisecond
	for key, bk := range b.buckets {
		if now.Sub(bk.lastRefill) >= evictAfter {
			delete(b.buckets, key)
		}
	}
	b.nextSweep = now.Add(evictAfter)
}

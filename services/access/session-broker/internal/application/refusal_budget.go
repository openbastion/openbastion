package application

import (
	"math"
	"sync"
	"time"
)

// What a user's refused reads may write to the audit (ADR-0020): a burst, then a steady
// rate. The defaults are the strict ones — and there is no "unlimited" and no "off": a
// value outside the bounds stops the Broker.
const (
	DefaultReadAuditBurst         = 10
	DefaultReadAuditRatePerMinute = 6
	MaxReadAuditBurst             = 1000
	MaxReadAuditRatePerMinute     = 600
)

// RefusalBudget decides how many of the refusals of ONE identity are written to the audit
// trail. A refusal is always a refusal — the answer never depends on this — but what a
// refusal writes must be bounded, or being refused would be a way for any holder of a
// token to write into the signed trail as often as it likes (ADR-0014, ADR-0016).
//
// It is a token bucket per key, the same model as the Gateway's limiter (ADR-0014): a key
// may have `burst` refusals written at once, and then one more every minute/perMinute. It is
// not shared with the Gateway's: that one lives in an internal package of another module,
// and what it answers (a retry delay) is not what is needed here. The key is the verified
// identity the Gateway named — a finite set of authenticated users, not of addresses — and
// a bucket that has had time to fill again is dropped, so what is held is what has refused
// something recently. Per process: with N replicas, N times the budget.
type RefusalBudget struct {
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

// NewRefusalBudget is a budget of `burst` refusals, with `perMinute` given back every
// minute. A value that is not positive gets the default: a budget built by hand is the
// strict one.
func NewRefusalBudget(burst, perMinute int) *RefusalBudget {
	if burst <= 0 {
		burst = DefaultReadAuditBurst
	}
	if perMinute <= 0 {
		perMinute = DefaultReadAuditRatePerMinute
	}
	return &RefusalBudget{
		buckets: map[string]*refusalBucket{}, capacity: float64(burst),
		refill: time.Minute / time.Duration(perMinute), now: time.Now,
	}
}

// WithClock replaces the clock; for tests.
func (b *RefusalBudget) WithClock(now func() time.Time) *RefusalBudget {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.now = now
	return b
}

// Burst and RatePerMinute say what the budget really is, for the line the Broker writes
// at start-up.
func (b *RefusalBudget) Burst() int { return int(b.capacity) }
func (b *RefusalBudget) RatePerMinute() int {
	return int(math.Round(float64(time.Minute) / float64(b.refill)))
}

// Tracked is how many identities the budget holds a bucket for: what the memory is made of.
func (b *RefusalBudget) Tracked() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.buckets)
}

// Take spends one token of key. write says whether this refusal is written to the audit;
// firstUnwritten is true for the first one that is not since this key last had one written
// — what a log line is for, instead of one per refusal.
func (b *RefusalBudget) Take(key string) (write, firstUnwritten bool) {
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
func (b *RefusalBudget) sweep(now time.Time) {
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

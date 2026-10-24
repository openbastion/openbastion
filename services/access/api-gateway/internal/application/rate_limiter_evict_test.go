package application

// Evicting the buckets that have been idle long enough to be full (ADR-0014) must not change
// a single decision: a full bucket is a bucket that never existed. The proof is a comparison,
// decision by decision, with a reference that never evicts anything — over long random
// sequences whose time steps are placed on purpose around every threshold.

import (
	"fmt"
	"math/rand"
	"testing"
	"time"
)

// neverEvicts is the limiter as it was before: the same arithmetic, one bucket per key for ever.
type neverEvicts struct {
	buckets  map[string]*bucket
	capacity float64
	refill   time.Duration
}

func (n *neverEvicts) take(key string, now time.Time) Decision {
	b, ok := n.buckets[key]
	if !ok {
		b = &bucket{tokens: n.capacity, lastRefill: now}
		n.buckets[key] = b
	}
	b.tokens += now.Sub(b.lastRefill).Seconds() * (1.0 / n.refill.Seconds())
	if b.tokens > n.capacity {
		b.tokens = n.capacity
	}
	b.lastRefill = now
	if b.tokens < 1 {
		d := Decision{RetryAfter: time.Duration(ceilNs((1 - b.tokens) * float64(n.refill))), NewEpisode: !b.refusing}
		b.refusing = true
		return d
	}
	b.tokens--
	b.refusing = false
	return Decision{Allowed: true}
}

func ceilNs(f float64) float64 {
	i := float64(int64(f))
	if f > i {
		return i + 1
	}
	return i
}

func TestEviction_NeverChangesADecision(t *testing.T) {
	for _, c := range []struct {
		capacity int
		refill   time.Duration
	}{{1, 10 * time.Second}, {3, 10 * time.Millisecond}, {10, 10 * time.Second}, {60, time.Second}, {5, time.Minute}, {1, time.Nanosecond * 7},
		// The ones where float arithmetic lands UNDER the capacity at the very moment a bucket
		// has had time to be full (a drained bucket idle for exactly capacity × refill has
		// 0.9999999999999999 tokens, not 1): evicting there, without a margin, would hand back a
		// request that the bucket kept would refuse. These are what the margin is for.
		{1, 13 * time.Millisecond}, {2, 13 * time.Millisecond}, {3, 3 * time.Millisecond}, {10, 3 * time.Millisecond}, {60, 3 * time.Millisecond}} {
		full := time.Duration(float64(c.capacity) * float64(c.refill))
		evictAfter := full + full/10 + time.Millisecond
		steps := []time.Duration{0, 1, c.refill / 2, c.refill, c.refill + 1, full - 1, full, full + 1,
			evictAfter - 1, evictAfter, evictAfter + 1, 3 * full, 10 * evictAfter}
		for seed := int64(1); seed <= 5; seed++ {
			t.Run(fmt.Sprintf("capacity %d every %v, seed %d", c.capacity, c.refill, seed), func(t *testing.T) {
				rng := rand.New(rand.NewSource(seed))
				now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
				real := NewRateLimiter(c.capacity, c.refill).WithClock(func() time.Time { return now })
				ref := &neverEvicts{buckets: map[string]*bucket{}, capacity: float64(c.capacity), refill: c.refill}
				for i := 0; i < 20000; i++ {
					now = now.Add(steps[rng.Intn(len(steps))])
					key := fmt.Sprint("k", rng.Intn(8))
					got, want := real.Take(key), ref.take(key, now)
					if got != want {
						t.Fatalf("operation %d (key %s, %v after the start): with eviction %+v, without %+v", i, key, now.Sub(time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)), got, want)
					}
				}
			})
		}
	}
}

// What eviction is for: the map stops growing with time, on an endpoint anyone can reach.
func TestEviction_TheMapStopsGrowingWithTime_AndKeepsWhatIsStillInUse(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(5, time.Minute).WithClock(func() time.Time { return now }) // full again after 5 min

	for i := 0; i < 10000; i++ {
		rl.Take(fmt.Sprint("addr-", i))
	}
	if len(rl.buckets) != 10000 {
		t.Fatalf("%d buckets after 10000 distinct keys, want 10000", len(rl.buckets))
	}
	now = now.Add(4 * time.Minute)
	for i := 0; i < 3; i++ {
		rl.Take("in-use") // drained a little, and recently seen
	}
	now = now.Add(2 * time.Minute) // 6 min since the 10000 were seen, 2 since "in-use"
	rl.Take("probe")
	if len(rl.buckets) != 2 {
		t.Fatalf("%d buckets kept, want 2 (the one in use and the probe): the idle ones are not evicted", len(rl.buckets))
	}
	// What was in use kept its state: 5 tokens, 3 taken, 2 refilled in 2 minutes: 4 left.
	taken := 0
	for rl.Take("in-use").Allowed {
		taken++
		if taken > 10 {
			t.Fatal("no end to the tokens")
		}
	}
	if taken != 4 {
		t.Fatalf("the bucket that was in use allowed %d more, want 4 (5 − 3 + 2 refilled): its state was lost", taken)
	}

	// A day later, a single request clears the rest.
	now = now.Add(24 * time.Hour)
	rl.Take("later")
	if len(rl.buckets) != 1 {
		t.Fatalf("%d buckets a day later, want 1", len(rl.buckets))
	}
}

// A bucket that is not full yet must never be evicted: that would give it tokens it has
// not earned, which is the whole of what the limiter is for.
func TestEviction_ADrainedBucketIsNotForgottenBeforeItIsFull(t *testing.T) {
	now := time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)
	rl := NewRateLimiter(3, 10*time.Second).WithClock(func() time.Time { return now }) // full again after 30 s
	for rl.Take("k").Allowed {
	}
	rl.Take("trigger") // a sweep is due on every call that is after the previous one's deadline
	now = now.Add(20 * time.Second)
	rl.Take("trigger")
	rl.Take("trigger")
	if rl.Take("k").Allowed != true { // 2 tokens have refilled in 20 s: allowed
		t.Fatal("two tokens had refilled in 20 s and the request was refused")
	}
	if !rl.Take("k").Allowed {
		t.Fatal("the second refilled token was refused")
	}
	if rl.Take("k").Allowed {
		t.Fatal("a third request was allowed: the bucket had been forgotten and started full again")
	}
}

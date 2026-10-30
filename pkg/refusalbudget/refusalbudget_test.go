package refusalbudget_test

// The budget of what refused reads write to the audit (ADR-0020): a token bucket per
// identity — a burst, then a steady rate — that is each identity's own, that is forgotten
// once it has had time to fill again, and that a clock which goes back cannot bend.

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/refusalbudget"
)

func budgetAt(burst, perMinute int) (*refusalbudget.Budget, *fakeClock) {
	clock := &fakeClock{t: time.Date(2026, 10, 29, 9, 0, 0, 0, time.UTC)}
	return refusalbudget.New(burst, perMinute).WithClock(clock.Now), clock
}

// written counts how many of n refusals of key are written, and the first-unwritten flags.
func written(b *refusalbudget.Budget, key string, n int) (w int, firsts int) {
	for i := 0; i < n; i++ {
		write, first := b.Take(key)
		if write {
			w++
		}
		if first {
			firsts++
		}
	}
	return
}

func TestRefusalBudget_ABurstIsWritten_ThenNothing_UntilATokenComesBack(t *testing.T) {
	b, clock := budgetAt(3, 6) // 3 at once, then one every 10 s
	if w, _ := written(b, "u1", 10); w != 3 {
		t.Fatalf("%d written out of 10 at once, want the burst of 3", w)
	}
	clock.t = clock.t.Add(9 * time.Second)
	if w, _ := written(b, "u1", 1); w != 0 {
		t.Fatal("a refusal 9 s later was written: the token comes back after 10 s")
	}
	clock.t = clock.t.Add(1 * time.Second)
	if w, _ := written(b, "u1", 1); w != 1 {
		t.Fatal("a refusal 10 s after the burst was not written: one token has come back")
	}
	if w, _ := written(b, "u1", 1); w != 0 {
		t.Fatal("a second refusal at the same instant was written: only one token came back")
	}
}

func TestRefusalBudget_TheRateIsPerMinute(t *testing.T) {
	for _, perMinute := range []int{1, 6, 60, 600} {
		t.Run(fmt.Sprint(perMinute, " a minute"), func(t *testing.T) {
			b, clock := budgetAt(1, perMinute)
			if w, _ := written(b, "u1", 1); w != 1 {
				t.Fatal("the burst of one was not written")
			}
			// A minute later, exactly `perMinute` more are written out of however many come.
			clock.t = clock.t.Add(time.Minute)
			if w, _ := written(b, "u1", perMinute+50); w != 1 {
				t.Fatalf("%d written at the end of a minute, want the burst of 1 (a bucket does not hold more)", w)
			}
			total := 0
			for i := 0; i < perMinute; i++ {
				clock.t = clock.t.Add(time.Minute / time.Duration(perMinute))
				w, _ := written(b, "u1", 3)
				total += w
			}
			if total != perMinute {
				t.Fatalf("%d written over a minute spaced at the rate, want %d", total, perMinute)
			}
		})
	}
}

func TestRefusalBudget_ABucketNeverHoldsMoreThanTheBurst(t *testing.T) {
	b, clock := budgetAt(3, 6)
	written(b, "u1", 3)
	clock.t = clock.t.Add(24 * time.Hour)
	if w, _ := written(b, "u1", 10); w != 3 {
		t.Fatalf("%d written after a day, want the burst of 3: time stores nothing beyond it", w)
	}
}

// The sweep runs once in a while, not at every call. A bucket that has been idle for as long
// as it takes to fill, but that the sweep has not dropped yet, must still hold no more than
// the burst: what a key may have written at once is the burst, not "the burst, and what the
// time since the last sweep has added".
func TestRefusalBudget_ABucketNeverHoldsMoreThanTheBurst_EvenBeforeTheSweepHasDroppedIt(t *testing.T) {
	b, clock := budgetAt(10, 6) // a token every 10 s: full after 100 s, swept from 110.001 s on
	written(b, "u1", 10)        // spent at once; the first call ran the sweep, the next is due in 110.001 s
	clock.t = clock.t.Add(110 * time.Second)
	if n := b.Tracked(); n != 1 {
		t.Fatalf("setup: %d held, want the one that was spent", n)
	}
	if w, _ := written(b, "u1", 30); w != 10 {
		t.Fatalf("%d written 110 s after the burst was spent, want the burst of 10 and not one more: the sweep had not run, and the bucket must still be capped", w)
	}
}

// What the sweep drops is what has had time to fill again — not what has merely been idle.
// A key that spent its only token 6 s ago has 0.6 of a token back: it is refused, and it is
// the same whether the sweep ran just before or not.
func TestRefusalBudget_ASweepKeepsABucketThatIsNotFullAgain(t *testing.T) {
	b, clock := budgetAt(1, 6) // a token every 10 s: swept from 11.001 s on
	written(b, "other", 1)     // the sweep runs now; the next is due in 11.001 s
	clock.t = clock.t.Add(5 * time.Second)
	if w, _ := written(b, "u1", 1); w != 1 {
		t.Fatalf("setup: %d written, want the one token", w)
	}
	clock.t = clock.t.Add(6*time.Second + time.Millisecond) // the sweep is due; u1 has been idle 6.001 s
	if w, _ := written(b, "u1", 1); w != 0 {
		t.Fatalf("%d written 6 s after the only token was spent: the sweep dropped a bucket that was not full again, and it decided as a new one", w)
	}
}

func TestRefusalBudget_EachIdentityHasItsOwn(t *testing.T) {
	b, _ := budgetAt(2, 6)
	written(b, "mallory", 10)
	if w, _ := written(b, "bob", 5); w != 2 {
		t.Fatalf("Bob had %d written, want his own burst of 2: Mallory spent hers, not his", w)
	}
	if w, _ := written(b, "mallory", 1); w != 0 {
		t.Fatal("Mallory's budget came back because somebody else used theirs")
	}
}

// What is told to log is the FIRST refusal that is not written, not every one: a prober
// does not get a log line per attempt either.
func TestRefusalBudget_TheFirstUnwrittenRefusalIsTold_OncePerEpisode(t *testing.T) {
	b, clock := budgetAt(2, 6)
	if w, first := written(b, "u1", 2); w != 2 || first != 0 {
		t.Fatalf("within the burst: %d written, %d firsts, want 2 and 0", w, first)
	}
	if w, first := written(b, "u1", 20); w != 0 || first != 1 {
		t.Fatalf("20 more at once: %d written, %d firsts, want none written and ONE first", w, first)
	}
	clock.t = clock.t.Add(10 * time.Second) // a token comes back, is written, and the next episode begins
	if w, first := written(b, "u1", 5); w != 1 || first != 1 {
		t.Fatalf("after a token: %d written, %d firsts, want 1 and 1 (a new episode)", w, first)
	}
}

func TestRefusalBudget_AValueThatIsNotPositiveIsTheStrictDefault(t *testing.T) {
	for _, c := range [][2]int{{0, 0}, {-1, -5}, {0, 7}, {5, 0}} {
		b := refusalbudget.New(c[0], c[1])
		burst, rate := c[0], c[1]
		if burst <= 0 {
			burst = refusalbudget.DefaultBurst
		}
		if rate <= 0 {
			rate = refusalbudget.DefaultRatePerMinute
		}
		if b.Burst() != burst || b.RatePerMinute() != rate {
			t.Fatalf("NewRefusalBudget(%d, %d) is %d and %d a minute, want %d and %d", c[0], c[1], b.Burst(), b.RatePerMinute(), burst, rate)
		}
	}
	if refusalbudget.DefaultBurst != 10 || refusalbudget.DefaultRatePerMinute != 6 ||
		refusalbudget.MaxBurst != 1000 || refusalbudget.MaxRatePerMinute != 600 {
		t.Fatal("the defaults and bounds are 10, 6, 1000 and 600 (the same as the budgets of ADR-0014 and ADR-0016)")
	}
}

func TestRefusalBudget_SaysTheRateItReallyAppliesPerMinute(t *testing.T) {
	for _, n := range []int{1, 3, 7, 13, 59, 600} {
		if got := refusalbudget.New(5, n).RatePerMinute(); got != n {
			t.Fatalf("a budget of %d a minute says %d", n, got)
		}
	}
}

// A bucket that has had the time to fill again decides as one that never existed, so it is
// dropped; one that is still short of tokens is not — dropping it would give back what it
// spent.
func TestRefusalBudget_MemoryHoldsOnlyWhatRefusedRecently(t *testing.T) {
	b, clock := budgetAt(3, 6) // full again 30 s after the last refusal
	for i := 0; i < 100; i++ {
		written(b, fmt.Sprintf("u%d", i), 1)
	}
	if n := b.Tracked(); n != 100 {
		t.Fatalf("%d identities held, want 100", n)
	}
	clock.t = clock.t.Add(20 * time.Second) // not yet full again
	written(b, "later", 1)
	if n := b.Tracked(); n != 101 {
		t.Fatalf("%d held at 20 s: a bucket that is not full again must be kept, want 101", n)
	}
	clock.t = clock.t.Add(60 * time.Second)
	written(b, "later", 1)
	if n := b.Tracked(); n != 1 {
		t.Fatalf("%d held after the others had time to fill, want only the identity that refused just now", n)
	}
}

func TestRefusalBudget_ADroppedBucketDecidesAsANewOne(t *testing.T) {
	b, clock := budgetAt(3, 6)
	written(b, "u1", 3) // spent
	clock.t = clock.t.Add(5 * time.Minute)
	written(b, "other", 1) // the sweep runs
	if b.Tracked() != 1 {
		t.Fatalf("setup: %d held, want 1", b.Tracked())
	}
	if w, _ := written(b, "u1", 10); w != 3 {
		t.Fatalf("%d written for an identity that had been dropped, want the full burst of 3", w)
	}
}

// A clock that goes back (an adjustment, a test) gives nothing and takes nothing.
func TestRefusalBudget_AClockThatGoesBackBendsNothing(t *testing.T) {
	b, clock := budgetAt(3, 6)
	written(b, "u1", 3)
	clock.t = clock.t.Add(-time.Hour)
	if w, _ := written(b, "u1", 5); w != 0 {
		t.Fatalf("%d written after the clock went back an hour: it must not give tokens", w)
	}
	clock.t = clock.t.Add(time.Hour + 10*time.Second)
	if w, _ := written(b, "u1", 5); w != 1 {
		t.Fatalf("%d written 10 s after the original instant, want 1: going back must not have taken a token either", w)
	}

	// Nor does it take from a bucket that still has tokens: two are left, and going back an
	// hour is not a way to find them gone.
	b2, clock2 := budgetAt(3, 6)
	written(b2, "u1", 1)
	clock2.t = clock2.t.Add(-time.Hour)
	if w, _ := written(b2, "u1", 5); w != 2 {
		t.Fatalf("%d written after the clock went back an hour with two tokens left, want 2: it must not take tokens", w)
	}
}

func TestRefusalBudget_IsSafeForConcurrentUse(t *testing.T) {
	b := refusalbudget.New(50, 6)
	var wg sync.WaitGroup
	var mu sync.Mutex
	total := 0
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w, _ := written(b, "u1", 100)
			mu.Lock()
			total += w
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 50 {
		t.Fatalf("%d written by 800 concurrent refusals, want exactly the burst of 50", total)
	}
}

// fakeClock is a clock the test moves by hand.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

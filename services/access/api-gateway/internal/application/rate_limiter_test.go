package application_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
)

func TestRateLimiter_AllowsUpToCapacityThenRejects(t *testing.T) {
	rl := application.NewRateLimiter(3, time.Minute)

	for i := 0; i < 3; i++ {
		if !rl.Allow("client-a") {
			t.Fatalf("expected request %d to be allowed within capacity", i+1)
		}
	}
	if rl.Allow("client-a") {
		t.Fatal("expected the 4th request to be rejected once capacity is exhausted")
	}
}

func TestRateLimiter_DifferentKeysAreIndependent(t *testing.T) {
	rl := application.NewRateLimiter(1, time.Minute)

	if !rl.Allow("client-a") {
		t.Fatal("expected client-a's first request to be allowed")
	}
	if rl.Allow("client-a") {
		t.Fatal("expected client-a's second request to be rejected")
	}
	if !rl.Allow("client-b") {
		t.Fatal("expected client-b to have its own, independent bucket")
	}
}

func TestRateLimiter_RefillsOverTime(t *testing.T) {
	rl := application.NewRateLimiter(1, 10*time.Millisecond)

	if !rl.Allow("client-a") {
		t.Fatal("expected the first request to be allowed")
	}
	if rl.Allow("client-a") {
		t.Fatal("expected the immediate second request to be rejected")
	}

	time.Sleep(15 * time.Millisecond)

	if !rl.Allow("client-a") {
		t.Fatal("expected a request after the refill interval to be allowed")
	}
}

// ---- ADR-0014: units, truthful refusals, episodes ------------------------------------

// fakeClock is a clock a test moves by hand.
type fakeClock struct{ t time.Time }

func newFakeClock() *fakeClock               { return &fakeClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)} }
func (c *fakeClock) Now() time.Time          { return c.t }
func (c *fakeClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// The second parameter is the time to accumulate ONE token. That is what the Gateway got
// wrong for authenticated traffic (a burst of 60 and then one per minute, under a comment
// that said "60 per minute"), so the units are pinned by what they let through.
func TestRateLimiter_TheUnitsAreWhatTheyAreCalled(t *testing.T) {
	steady := func(capacity int, refill time.Duration) (burst, allowedOverTenMinutes int) {
		clock := newFakeClock()
		rl := application.NewRateLimiter(capacity, refill).WithClock(clock.Now)
		for rl.Allow("k") {
			burst++
		}
		for s := 0; s < 600; s++ { // one attempt every second, for ten minutes
			clock.Advance(time.Second)
			if rl.Allow("k") {
				allowedOverTenMinutes++
			}
		}
		return
	}
	if burst, n := steady(60, time.Second); burst != 60 || n != 600 {
		t.Fatalf("(60, 1s): burst %d and %d allowed in ten minutes, want 60 and 600 — sixty per minute once the burst is spent", burst, n)
	}
	if burst, n := steady(60, time.Minute); burst != 60 || n != 10 {
		t.Fatalf("(60, 1min): burst %d and %d allowed in ten minutes, want 60 and 10 — a burst, then ONE per minute", burst, n)
	}
	if burst, n := steady(5, time.Minute); burst != 5 || n != 10 {
		t.Fatalf("(5, 1min) — the login limiter: burst %d and %d allowed in ten minutes, want 5 and 10", burst, n)
	}
}

func TestRateLimiter_ARefusalSaysHowLongToWait_AndTheAnswerIsRoundedUp(t *testing.T) {
	clock := newFakeClock()
	rl := application.NewRateLimiter(1, 10*time.Second).WithClock(clock.Now)

	if d := rl.Take("k"); !d.Allowed || d.RetryAfter != 0 || d.NewEpisode {
		t.Fatalf("first request: %+v, want allowed with nothing to wait", d)
	}
	d := rl.Take("k")
	if d.Allowed || d.RetryAfter != 10*time.Second {
		t.Fatalf("immediately after: %+v, want refused with 10 s to wait", d)
	}
	clock.Advance(4 * time.Second)
	if d := rl.Take("k"); d.Allowed || d.RetryAfter != 6*time.Second {
		t.Fatalf("4 s later: %+v, want refused with 6 s to wait", d)
	}
	clock.Advance(6*time.Second - time.Millisecond)
	d = rl.Take("k")
	if d.Allowed || d.RetryAfter != time.Millisecond {
		t.Fatalf("a millisecond too early: %+v, want refused with 1 ms to wait", d)
	}
	if got := d.RetryAfterSeconds(); got != 1 {
		t.Fatalf("1 ms to wait is told as %d s, want 1: never zero, a client told 0 retries at once", got)
	}
	clock.Advance(time.Millisecond)
	if !rl.Take("k").Allowed {
		t.Fatal("after the 6 s that were announced the request is still refused")
	}

	for _, c := range []struct {
		wait time.Duration
		want int
	}{{10 * time.Second, 10}, {6200 * time.Millisecond, 7}, {time.Nanosecond, 1}, {0, 1}, {59*time.Second + 1, 60}} {
		if got := (application.Decision{RetryAfter: c.wait}).RetryAfterSeconds(); got != c.want {
			t.Fatalf("RetryAfterSeconds(%v) = %d, want %d (rounded up, at least 1)", c.wait, got, c.want)
		}
	}
}

// A log line is written for the first refusal of an episode, not for every refused request.
func TestRateLimiter_AnEpisodeOfRefusalsIsAnnouncedOnce(t *testing.T) {
	clock := newFakeClock()
	rl := application.NewRateLimiter(1, 10*time.Second).WithClock(clock.Now)
	rl.Take("k") // allowed
	var announced []bool
	for i := 0; i < 4; i++ {
		announced = append(announced, rl.Take("k").NewEpisode)
	}
	if fmt.Sprint(announced) != "[true false false false]" {
		t.Fatalf("four refusals in a row announced %v, want only the first", announced)
	}
	clock.Advance(10 * time.Second)
	if !rl.Take("k").Allowed {
		t.Fatal("the key was not allowed again after the refill")
	}
	if d := rl.Take("k"); d.Allowed || !d.NewEpisode {
		t.Fatalf("a refusal after having been allowed again: %+v, want a new episode", d)
	}
	// Another key has its own episodes.
	if d := rl.Take("other"); !d.Allowed || d.NewEpisode {
		t.Fatalf("another key: %+v", d)
	}
}

func TestNewSessionRequestLimiter_TheStrictDefaults_AndTheUnitsOfAMinute(t *testing.T) {
	if application.DefaultSessionBurst != 10 || application.DefaultSessionRatePerMinute != 6 ||
		application.MaxSessionBurst != 1000 || application.MaxSessionRatePerMinute != 600 {
		t.Fatalf("the defaults or the maxima changed: %d/%d, up to %d/%d", application.DefaultSessionBurst,
			application.DefaultSessionRatePerMinute, application.MaxSessionBurst, application.MaxSessionRatePerMinute)
	}
	for _, c := range []struct {
		burst, perMinute int
		wantBurst        int
		wantRefill       time.Duration
	}{{0, 0, 10, 10 * time.Second}, {-3, -1, 10, 10 * time.Second}, {3, 60, 3, time.Second}, {7, 6, 7, 10 * time.Second}, {1, 600, 1, 100 * time.Millisecond}} {
		l := application.NewSessionRequestLimiter(c.burst, c.perMinute)
		if l.Capacity() != c.wantBurst || l.Refill() != c.wantRefill {
			t.Fatalf("NewSessionRequestLimiter(%d, %d) = burst %d, one every %v; want %d and %v",
				c.burst, c.perMinute, l.Capacity(), l.Refill(), c.wantBurst, c.wantRefill)
		}
	}
}

// ADR-0016, ADR-0017: the budget of approve, reject, connect and terminate has its own constants and its own
// constructor. Their values are today those of POST /sessions, so a test cannot tell which
// constants the constructor reads; what it pins is the values themselves.
func TestNewSessionActionLimiter_TheStrictDefaults_AndTheUnitsOfAMinute(t *testing.T) {
	if application.DefaultSessionActionBurst != 10 || application.DefaultSessionActionRatePerMinute != 6 ||
		application.MaxSessionActionBurst != 1000 || application.MaxSessionActionRatePerMinute != 600 {
		t.Fatalf("the defaults or the maxima changed: %d/%d, up to %d/%d", application.DefaultSessionActionBurst,
			application.DefaultSessionActionRatePerMinute, application.MaxSessionActionBurst, application.MaxSessionActionRatePerMinute)
	}
	for _, c := range []struct {
		burst, perMinute int
		wantBurst        int
		wantRefill       time.Duration
	}{{0, 0, 10, 10 * time.Second}, {-3, -1, 10, 10 * time.Second}, {3, 60, 3, time.Second}, {7, 6, 7, 10 * time.Second}, {1, 600, 1, 100 * time.Millisecond}} {
		l := application.NewSessionActionLimiter(c.burst, c.perMinute)
		if l.Capacity() != c.wantBurst || l.Refill() != c.wantRefill {
			t.Fatalf("NewSessionActionLimiter(%d, %d) = burst %d, one every %v; want %d and %v",
				c.burst, c.perMinute, l.Capacity(), l.Refill(), c.wantBurst, c.wantRefill)
		}
	}
}

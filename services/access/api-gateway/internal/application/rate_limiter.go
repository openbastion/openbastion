// Package application holds the API Gateway's own logic: rate limiting
// and the TokenVerifier port. The actual HTTP routing/forwarding lives in
// interfaces/, since that's fundamentally what a gateway does — but the
// two policies here (bucket accounting, and "the Gateway's verified
// identity always overrides client claims") are treated as logic worth
// isolating and testing on their own, not incidental to HTTP wiring.
package application

import (
	"context"
	"math"
	"sync"
	"time"
)

// TokenVerifier is the port to Authentication's token verification
// (doc 07's RequestContext.actor_user_id/actor_roles are resolved from
// this — the Gateway trusts only this, never a client's own claims).
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (userID, username string, roles []string, err error)
}

// RateLimiter is an in-memory token bucket per key — the client IP for the
// requests that have not been authenticated yet, the verified user for what an
// authenticated user may do (ADR-0014): doc 00 §9's brute-force protection and
// general abuse protection, one of the Gateway's stated responsibilities
// (doc 00 §4.1: "rate-limiting"). Per-process only; a multi-replica Gateway
// needs a shared store (Redis, doc 00 §10) — a v1.0 concern.
//
// The two parameters are a burst and a refill interval: a key may make `capacity`
// requests at once, and then one more every `refillEvery`. NewRateLimiter(60,
// time.Second) is therefore 60 per minute once the burst is spent;
// NewRateLimiter(60, time.Minute) is a burst of 60 and then ONE per minute.
type RateLimiter struct {
	mu        sync.Mutex
	buckets   map[string]*bucket
	capacity  float64
	refill    time.Duration // time to accumulate one token
	now       func() time.Time
	nextSweep time.Time
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
	refusing   bool // the last request of this key was refused
}

// Decision is what Take says about one request.
type Decision struct {
	Allowed bool
	// RetryAfter is what is missing for the next token; zero when Allowed.
	RetryAfter time.Duration
	// NewEpisode is true for the first refusal since this key was last allowed:
	// what a log line should be written for, instead of one per refused request.
	NewEpisode bool
}

func NewRateLimiter(capacity int, refillEvery time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: map[string]*bucket{}, capacity: float64(capacity), refill: refillEvery,
		now: time.Now,
	}
}

// WithClock replaces the clock; for tests.
func (r *RateLimiter) WithClock(now func() time.Time) *RateLimiter {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.now = now
	return r
}

// Capacity is the burst; Refill is the time between two tokens once it is spent.
func (r *RateLimiter) Capacity() int         { return int(r.capacity) }
func (r *RateLimiter) Refill() time.Duration { return r.refill }

// Allow reports whether the caller identified by key may proceed, and
// consumes one token if so.
func (r *RateLimiter) Allow(key string) bool { return r.Take(key).Allowed }

// Take is Allow, with what a caller needs to answer a refused request truthfully.
func (r *RateLimiter) Take(key string) Decision {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
	r.sweep(now)
	b, ok := r.buckets[key]
	if !ok {
		b = &bucket{tokens: r.capacity, lastRefill: now}
		r.buckets[key] = b
	}

	elapsed := now.Sub(b.lastRefill)
	refillRate := 1.0 / r.refill.Seconds()
	b.tokens += elapsed.Seconds() * refillRate
	if b.tokens > r.capacity {
		b.tokens = r.capacity
	}
	b.lastRefill = now

	if b.tokens < 1 {
		// Rounded UP to the nanosecond: float arithmetic can land a hair under, and a
		// conversion to Duration truncates — which would tell a client to come back
		// a moment too early.
		d := Decision{RetryAfter: time.Duration(math.Ceil((1 - b.tokens) * float64(r.refill))), NewEpisode: !b.refusing}
		b.refusing = true
		return d
	}
	b.tokens--
	b.refusing = false
	return Decision{Allowed: true}
}

// sweep drops the buckets that have been idle long enough to be full again. A
// full bucket decides exactly as a bucket that never existed, so nothing any
// request is told changes; what stops is the map growing for as long as the
// process lives (one bucket per source address, on an endpoint anyone can reach).
// The margin is there so that floating-point rounding can never make a bucket
// that is dropped differ from a new one.
func (r *RateLimiter) sweep(now time.Time) {
	if now.Before(r.nextSweep) {
		return
	}
	full := time.Duration(r.capacity * float64(r.refill))
	evictAfter := full + full/10 + time.Millisecond
	for key, b := range r.buckets {
		if now.Sub(b.lastRefill) >= evictAfter {
			delete(r.buckets, key)
		}
	}
	r.nextSweep = now.Add(evictAfter)
}

// What a user may ask of POST /sessions (ADR-0014): a burst, then a steady rate.
// The defaults are the strict ones; what is above the maximum is not a setting
// anybody gets, because there is no "unlimited".
const (
	DefaultSessionBurst         = 10
	DefaultSessionRatePerMinute = 6
	MaxSessionBurst             = 1000
	MaxSessionRatePerMinute     = 600

	// The per-user budget of the session actions that write on every call (ADR-0016,
	// ADR-0017): approve, reject, connect, terminate.
	DefaultSessionActionBurst         = 10
	DefaultSessionActionRatePerMinute = 6
	MaxSessionActionBurst             = 1000
	MaxSessionActionRatePerMinute     = 600

	// The per-address limits (ADR-0015). Their defaults are what the two limiters
	// have always really done — login: a burst of 5, then ONE a minute; authenticated
	// traffic: a burst of 60, then 60 a minute — so that making them adjustable
	// relaxes nothing until someone asks, by name.
	DefaultLoginBurst                 = 5
	MaxLoginBurst                     = 100
	DefaultLoginRatePerMinute         = 1
	MaxLoginRatePerMinute             = 60
	DefaultClientRequestBurst         = 60
	MaxClientRequestBurst             = 10000
	DefaultClientRequestRatePerMinute = 60
	MaxClientRequestRatePerMinute     = 6000
)

// perMinuteLimiter is a bucket of `burst` tokens that gets `perMinute` back every
// minute. A value that is not positive gets the default: a limiter built by hand is
// the strict one.
func perMinuteLimiter(burst, perMinute, defaultBurst, defaultPerMinute int) *RateLimiter {
	if burst <= 0 {
		burst = defaultBurst
	}
	if perMinute <= 0 {
		perMinute = defaultPerMinute
	}
	return NewRateLimiter(burst, time.Minute/time.Duration(perMinute))
}

// NewSessionRequestLimiter is the per-user budget of POST /sessions: `burst`
// requests at once, then `perMinute` per minute (ADR-0014).
func NewSessionRequestLimiter(burst, perMinute int) *RateLimiter {
	return perMinuteLimiter(burst, perMinute, DefaultSessionBurst, DefaultSessionRatePerMinute)
}

// NewSessionActionLimiter is the per-user budget of approve, reject, connect and
// terminate: `burst` actions at once, then `perMinute` per minute (ADR-0016, ADR-0017). It is not the
// budget of POST /sessions: asking for a session and then connecting to it is the
// ordinary pair, and spending one must not take the other away.
func NewSessionActionLimiter(burst, perMinute int) *RateLimiter {
	return perMinuteLimiter(burst, perMinute, DefaultSessionActionBurst, DefaultSessionActionRatePerMinute)
}

// NewLoginLimiter is the per-address limit of POST /auth/login: `burst` attempts at
// once, then `perMinute` per minute (ADR-0015). It is the brute-force protection of
// the one endpoint reachable without a token.
func NewLoginLimiter(burst, perMinute int) *RateLimiter {
	return perMinuteLimiter(burst, perMinute, DefaultLoginBurst, DefaultLoginRatePerMinute)
}

// NewClientRequestLimiter is the per-address limit of authenticated traffic, applied
// before the token is looked at: `burst` requests at once, then `perMinute` per
// minute (ADR-0015).
func NewClientRequestLimiter(burst, perMinute int) *RateLimiter {
	return perMinuteLimiter(burst, perMinute, DefaultClientRequestBurst, DefaultClientRequestRatePerMinute)
}

// RetryAfterSeconds is what a refused request is told to wait: the time that is
// missing for the next token, rounded UP to a whole second, never less than one.
func (d Decision) RetryAfterSeconds() int {
	s := int((d.RetryAfter + time.Second - 1) / time.Second)
	if s < 1 {
		return 1
	}
	return s
}

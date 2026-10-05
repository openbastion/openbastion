// Package application holds the API Gateway's own logic: rate limiting
// and the TokenVerifier port. The actual HTTP routing/forwarding lives in
// interfaces/, since that's fundamentally what a gateway does — but the
// two policies here (bucket accounting, and "the Gateway's verified
// identity always overrides client claims") are treated as logic worth
// isolating and testing on their own, not incidental to HTTP wiring.
package application

import (
	"context"
	"sync"
	"time"
)

// TokenVerifier is the port to Authentication's token verification
// (doc 07's RequestContext.actor_user_id/actor_roles are resolved from
// this — the Gateway trusts only this, never a client's own claims).
type TokenVerifier interface {
	VerifyToken(ctx context.Context, token string) (userID, username string, roles []string, err error)
}

// RateLimiter is a simple in-memory token bucket per key (client IP, or
// authenticated user once known) — doc 00 §9's brute-force protection and
// general abuse protection, one of the Gateway's stated responsibilities
// (doc 00 §4.1: "rate-limiting"). Per-process only; a multi-replica
// Gateway needs a shared store (Redis, doc 00 §10) — a v1.0 concern.
type RateLimiter struct {
	mu       sync.Mutex
	buckets  map[string]*bucket
	capacity float64
	refill   time.Duration // time to accumulate one full token
	now      func() time.Time
}

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

func NewRateLimiter(capacity int, refillEvery time.Duration) *RateLimiter {
	return &RateLimiter{
		buckets: map[string]*bucket{}, capacity: float64(capacity), refill: refillEvery,
		now: time.Now,
	}
}

// Allow reports whether the caller identified by key may proceed, and
// consumes one token if so.
func (r *RateLimiter) Allow(key string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := r.now()
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
		return false
	}
	b.tokens--
	return true
}

package application_test

import (
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

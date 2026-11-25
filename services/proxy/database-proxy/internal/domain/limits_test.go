package domain

import (
	"errors"
	"sync"
	"testing"
)

func TestConnectionLimiterEnforcesAllDimensionsAndReleases(t *testing.T) {
	limits := ConnectionLimits{MaxTotal: 2, MaxPerTarget: 1, MaxPerActor: 2, MaxPerSession: 1}
	limiter, err := NewConnectionLimiter(limits)
	if err != nil {
		t.Fatal(err)
	}
	release, err := limiter.Acquire("db-a", "actor-a", "session-a")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := limiter.Acquire("db-a", "actor-b", "session-b"); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("per-target limit error = %v", err)
	}
	if _, err := limiter.Acquire("db-b", "actor-a", "session-c"); err != nil {
		t.Fatalf("different target should be admitted: %v", err)
	}
	if _, err := limiter.Acquire("db-c", "actor-c", "session-d"); !errors.Is(err, ErrConnectionLimit) {
		t.Fatalf("global limit error = %v", err)
	}
	release()
	release()
	if _, err := limiter.Acquire("db-a", "actor-a", "session-e"); err != nil {
		t.Fatalf("released target slot was not available: %v", err)
	}
}

func TestConnectionLimiterRejectsInvalidOrUnboundedConfiguration(t *testing.T) {
	cases := []ConnectionLimits{
		{},
		{MaxTotal: 0, MaxPerTarget: 1, MaxPerActor: 1, MaxPerSession: 1},
		{MaxTotal: 10, MaxPerTarget: 11, MaxPerActor: 1, MaxPerSession: 1},
		{MaxTotal: 10, MaxPerTarget: 1, MaxPerActor: 0, MaxPerSession: 1},
		{MaxTotal: 10, MaxPerTarget: 1, MaxPerActor: 1, MaxPerSession: 2},
		{MaxTotal: 1 << 20, MaxPerTarget: 1, MaxPerActor: 1, MaxPerSession: 1},
	}
	for i, limits := range cases {
		if _, err := NewConnectionLimiter(limits); err == nil {
			t.Errorf("case %d accepted invalid limits: %+v", i, limits)
		}
	}
}

func TestConnectionLimiterConcurrentAcquireNeverExceedsLimit(t *testing.T) {
	limiter, err := NewConnectionLimiter(ConnectionLimits{MaxTotal: 4, MaxPerTarget: 4, MaxPerActor: 4, MaxPerSession: 1})
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	var releases []func()
	admitted := 0
	for i := range 32 {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			release, err := limiter.Acquire("db", "actor", string(rune('a'+i)))
			if err == nil {
				mu.Lock()
				admitted++
				releases = append(releases, release)
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if admitted != 4 {
		t.Fatalf("admitted %d connections, want 4", admitted)
	}
	for _, release := range releases {
		release()
	}
}

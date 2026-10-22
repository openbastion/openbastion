package infrastructure_test

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func pendingRequest(id string) *domain.Session {
	now := time.Now().UTC()
	return &domain.Session{
		ID: id, Status: domain.StatusPendingApproval, Protocol: "ssh", RequestedBy: "oncall",
		PrivilegedAccountID: "acc", Justification: "recorder down during P1", BreakGlass: true,
		CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), DurationMinutes: 20,
	}
}

func decidedAs(s *domain.Session, status domain.SessionStatus, by string) *domain.Session {
	cp := *s
	cp.Status, cp.DecidedBy = status, by
	at := time.Now().UTC()
	cp.DecidedAt = &at
	return &cp
}

// The compare-and-swap that makes a decision happen once (ADR-0011), on the in-memory store.
func TestInMemoryStore_SaveIfStatus_SwapsOnlyFromTheExpectedStatus(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	req := pendingRequest("s-1")
	if err := store.Save(ctx, req); err != nil {
		t.Fatal(err)
	}

	// Wrong expectation: nothing changes.
	swapped, err := store.SaveIfStatus(ctx, decidedAs(req, domain.StatusActive, "lead"), domain.StatusActive)
	if err != nil || swapped {
		t.Fatalf("swapped from the wrong status: %v %v", swapped, err)
	}
	if got, _ := store.Get(ctx, "s-1"); got.Status != domain.StatusPendingApproval || got.DecidedBy != "" {
		t.Fatalf("a refused swap changed the row: %+v", got)
	}

	// Right expectation: swaps, once.
	swapped, err = store.SaveIfStatus(ctx, decidedAs(req, domain.StatusActive, "lead"), domain.StatusPendingApproval)
	if err != nil || !swapped {
		t.Fatalf("did not swap from the expected status: %v %v", swapped, err)
	}
	got, _ := store.Get(ctx, "s-1")
	if got.Status != domain.StatusActive || got.DecidedBy != "lead" || got.DecidedAt == nil {
		t.Fatalf("stored = %+v", got)
	}
	if swapped, _ = store.SaveIfStatus(ctx, decidedAs(req, domain.StatusDenied, "other"), domain.StatusPendingApproval); swapped {
		t.Fatal("a second swap from the same status succeeded")
	}

	// An unknown id swaps nothing and is not an error.
	if swapped, err = store.SaveIfStatus(ctx, pendingRequest("ghost"), domain.StatusPendingApproval); swapped || err != nil {
		t.Fatalf("unknown id: %v %v", swapped, err)
	}
	if _, err := store.Get(ctx, "ghost"); err != domain.ErrNotFound {
		t.Fatalf("the swap of an unknown id created it: %v", err)
	}
}

func TestInMemoryStore_SaveIfStatus_OfManyRacingDecisionsExactlyOneWins(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	for round := 0; round < 50; round++ {
		req := pendingRequest("s-race")
		_ = store.Save(ctx, req)
		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []string
		for _, by := range []string{"a", "b", "c", "d", "e", "f"} {
			by := by
			wg.Add(1)
			go func() {
				defer wg.Done()
				if ok, _ := store.SaveIfStatus(ctx, decidedAs(req, domain.StatusActive, by), domain.StatusPendingApproval); ok {
					mu.Lock()
					winners = append(winners, by)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(winners) != 1 {
			t.Fatalf("round %d: %d winners (%v)", round, len(winners), winners)
		}
		if got, _ := store.Get(ctx, "s-race"); got.DecidedBy != winners[0] {
			t.Fatalf("round %d: %s won but the row says %q", round, winners[0], got.DecidedBy)
		}
	}
}

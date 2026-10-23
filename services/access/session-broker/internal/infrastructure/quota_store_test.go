package infrastructure_test

// CountPending and SaveIfUnderPendingLimit (ADR-0013) have one contract and two stores:
// the same assertions run against the in-memory store and, when a database is there,
// PostgreSQL. The last one is the one that matters: of many requests of one requester
// racing for the places left, exactly the places left are taken — across Broker replicas.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func quotaRow(id, by string, status domain.SessionStatus, expires time.Time) *domain.Session {
	return &domain.Session{
		ID: id, Status: status, Protocol: "ssh", RequestedBy: by, PrivilegedAccountID: "acc-q",
		Justification: "recorder down during P1 incident", BreakGlass: true,
		CreatedAt: expires.Add(-15 * time.Minute), ExpiresAt: expires, DurationMinutes: 20,
	}
}

func quotaCountContract(t *testing.T, store domain.SessionRepository, prefix string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond) // PostgreSQL TIMESTAMPTZ precision
	r, o := prefix+"requester", prefix+"other"

	for _, s := range []*domain.Session{
		quotaRow(prefix+"a", r, domain.StatusPendingApproval, now.Add(5*time.Minute)),
		quotaRow(prefix+"b", r, domain.StatusPendingApproval, now.Add(9*time.Minute)),
		quotaRow(prefix+"edge", r, domain.StatusPendingApproval, now),                        // its deadline is this very instant: still waiting
		quotaRow(prefix+"late", r, domain.StatusPendingApproval, now.Add(-time.Microsecond)), // a moment past it: no longer
		quotaRow(prefix+"active", r, domain.StatusActive, now.Add(time.Hour)),
		quotaRow(prefix+"denied", r, domain.StatusDenied, now.Add(time.Hour)),
		quotaRow(prefix+"terminated", r, domain.StatusTerminated, now.Add(time.Hour)),
		quotaRow(prefix+"expired", r, domain.StatusExpired, now.Add(time.Hour)),
		quotaRow(prefix+"theirs", o, domain.StatusPendingApproval, now.Add(5*time.Minute)),
	} {
		if err := store.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		by   string
		want int
	}{{r, 3}, {o, 1}, {prefix + "nobody", 0}} {
		got, err := store.CountPending(ctx, c.by, now)
		if err != nil || got != c.want {
			t.Fatalf("CountPending(%s) = %d, %v; want %d (waiting, not past the deadline, of that requester only)", c.by, got, err, c.want)
		}
	}
	// The same rows, a moment later: the edge request has just stopped waiting.
	if got, _ := store.CountPending(ctx, r, now.Add(time.Microsecond)); got != 2 {
		t.Fatalf("CountPending a microsecond later = %d, want 2", got)
	}
}

func quotaSaveContract(t *testing.T, store domain.SessionRepository, prefix string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	r, o := prefix+"requester", prefix+"other"

	// Two of R's waiting, and one that no longer counts.
	for _, s := range []*domain.Session{
		quotaRow(prefix+"w1", r, domain.StatusPendingApproval, now.Add(5*time.Minute)),
		quotaRow(prefix+"w2", r, domain.StatusPendingApproval, now.Add(6*time.Minute)),
		quotaRow(prefix+"old", r, domain.StatusPendingApproval, now.Add(-time.Minute)),
		quotaRow(prefix+"act", r, domain.StatusActive, now.Add(time.Hour)),
	} {
		if err := store.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}

	// At the limit: refused, and nothing is written.
	saved, err := store.SaveIfUnderPendingLimit(ctx, quotaRow(prefix+"n1", r, domain.StatusPendingApproval, now.Add(7*time.Minute)), 2, now)
	if err != nil || saved {
		t.Fatalf("two waiting, limit 2: saved=%v err=%v, want a refusal", saved, err)
	}
	if _, err := store.Get(ctx, prefix+"n1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a refused request was stored anyway: %v", err)
	}
	// One place left: taken.
	saved, err = store.SaveIfUnderPendingLimit(ctx, quotaRow(prefix+"n2", r, domain.StatusPendingApproval, now.Add(7*time.Minute)), 3, now)
	if err != nil || !saved {
		t.Fatalf("two waiting, limit 3: saved=%v err=%v, want it saved", saved, err)
	}
	got, err := store.Get(ctx, prefix+"n2")
	if err != nil || got.Status != domain.StatusPendingApproval || got.RequestedBy != r || got.PrivilegedAccountID != "acc-q" ||
		got.Justification != "recorder down during P1 incident" || !got.BreakGlass || got.DurationMinutes != 20 {
		t.Fatalf("what was saved is not the request: %+v (%v)", got, err)
	}
	// Now three wait: the same limit refuses.
	if saved, _ := store.SaveIfUnderPendingLimit(ctx, quotaRow(prefix+"n3", r, domain.StatusPendingApproval, now.Add(7*time.Minute)), 3, now); saved {
		t.Fatal("a third place was found where the limit is 3")
	}
	// Somebody else's quota is their own.
	if saved, err := store.SaveIfUnderPendingLimit(ctx, quotaRow(prefix+"o1", o, domain.StatusPendingApproval, now.Add(7*time.Minute)), 1, now); err != nil || !saved {
		t.Fatalf("another requester was refused for the first requester's queue: saved=%v err=%v", saved, err)
	}
}

func quotaRaceContract(t *testing.T, stores []domain.SessionRepository, prefix string) {
	t.Helper()
	ctx := context.Background()
	const workers, limit, rounds = 40, 3, 8
	for round := 0; round < rounds; round++ {
		by := fmt.Sprintf("%srace-%d", prefix, round)
		now := time.Now().UTC().Truncate(time.Microsecond)
		var wg sync.WaitGroup
		var mu sync.Mutex
		accepted := 0
		errs := []error{}
		start := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				s := quotaRow(fmt.Sprintf("%s-%d", by, i), by, domain.StatusPendingApproval, now.Add(10*time.Minute))
				saved, err := stores[i%len(stores)].SaveIfUnderPendingLimit(ctx, s, limit, now)
				mu.Lock()
				defer mu.Unlock()
				if err != nil {
					errs = append(errs, err)
				}
				if saved {
					accepted++
				}
			}(i)
		}
		close(start)
		wg.Wait()
		n, err := stores[0].CountPending(ctx, by, now)
		if len(errs) != 0 || accepted != limit || n != limit || err != nil {
			t.Fatalf("round %d: accepted=%d waiting=%d errors=%v; want exactly %d accepted and waiting", round, accepted, n, errs, limit)
		}
	}
}

func TestInMemoryStore_CountPending_CountsWhatIsWaitingForThatRequester(t *testing.T) {
	quotaCountContract(t, infrastructure.NewInMemoryStore(), "m-")
}

func TestInMemoryStore_SaveIfUnderPendingLimit_IsRefusedAtTheLimit_AndWritesNothing(t *testing.T) {
	quotaSaveContract(t, infrastructure.NewInMemoryStore(), "m-")
}

func TestInMemoryStore_SaveIfUnderPendingLimit_TakesExactlyThePlacesLeftUnderConcurrency(t *testing.T) {
	s := infrastructure.NewInMemoryStore()
	quotaRaceContract(t, []domain.SessionRepository{s}, "m-")
}

func TestPostgresStore_CountPending_CountsWhatIsWaitingForThatRequester(t *testing.T) {
	db := testDB(t)
	quotaCountContract(t, infrastructure.NewPostgresStore(db), uniqueID("qc")+"-")
}

func TestPostgresStore_SaveIfUnderPendingLimit_IsRefusedAtTheLimit_AndWritesNothing(t *testing.T) {
	db := testDB(t)
	quotaSaveContract(t, infrastructure.NewPostgresStore(db), uniqueID("qs")+"-")
}

// Two stores on two separate connection pools are two Broker replicas: only the
// database can serialise them.
func TestPostgresStore_SaveIfUnderPendingLimit_TakesExactlyThePlacesLeft_AcrossTwoReplicas(t *testing.T) {
	db1 := testDB(t)
	db2, err := infrastructure.OpenPostgres(context.Background(), testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	quotaRaceContract(t, []domain.SessionRepository{infrastructure.NewPostgresStore(db1), infrastructure.NewPostgresStore(db2)}, uniqueID("qr")+"-")
}

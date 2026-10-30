package infrastructure_test

// The expiry of domain.SessionRepository (ADR-0034), one contract for both stores, and the race
// of two replicas on PostgreSQL.

import (
	"context"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func expiryContract(t *testing.T, store domain.SessionRepository, run string) {
	ctx := context.Background()
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	for _, s := range []struct {
		id     string
		status domain.SessionStatus
		end    time.Time
	}{
		{"due_active", domain.StatusActive, now.Add(-time.Minute)},
		{"due_pending", domain.StatusPendingApproval, now.Add(-time.Second)},
		{"due_later", domain.StatusActive, now.Add(-time.Hour)},
		{"at_its_end", domain.StatusActive, now}, // its end is now: not yet past it
		{"running", domain.StatusActive, now.Add(time.Hour)},
		{"terminated", domain.StatusTerminated, now.Add(-time.Hour)},
		{"denied", domain.StatusDenied, now.Add(-time.Hour)},
	} {
		if err := store.Save(ctx, &domain.Session{ID: run + s.id, Status: s.status, Protocol: "ssh", RequestedBy: "u",
			PrivilegedAccountID: "acc", Justification: "j", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: s.end}); err != nil {
			t.Fatal(err)
		}
	}
	first, err := store.ExpireDue(ctx, now, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.ExpireDue(ctx, now, 2)
	if err != nil {
		t.Fatal(err)
	}
	ids := func(ss []*domain.Session) []string {
		var out []string
		for _, s := range ss {
			out = append(out, s.ID[len(run):])
			if s.Status != domain.StatusExpired {
				t.Fatalf("%s returned with status %s, want expired", s.ID, s.Status)
			}
		}
		return out
	}
	if got := fmt.Sprint(ids(first), ids(second)); got != "[due_later due_active] [due_pending]" {
		t.Fatalf("expired %s, want the three past their end, soonest end first, at most two at a time", got)
	}
	if again, _ := store.ExpireDue(ctx, now, 10); len(again) != 0 {
		t.Fatalf("expired again: %v", ids(again))
	}
	for id, want := range map[string]domain.SessionStatus{"due_active": domain.StatusExpired, "due_pending": domain.StatusExpired,
		"at_its_end": domain.StatusActive, "running": domain.StatusActive, "terminated": domain.StatusTerminated, "denied": domain.StatusDenied} {
		s, err := store.Get(ctx, run+id)
		if err != nil || s.Status != want {
			t.Fatalf("%s: %v %v, want %s", id, s, err, want)
		}
	}
	// A compare-and-swap on an expired session loses.
	s, _ := store.Get(ctx, run+"due_active")
	s.Status = domain.StatusTerminated
	if swapped, err := store.SaveIfStatus(ctx, s, domain.StatusActive); err != nil || swapped {
		t.Fatalf("terminating an expired session: %v %v", swapped, err)
	}

	// To audit: what was expired before `before`, until marked.
	if late, _ := store.ExpiriesToAudit(ctx, now, 10); len(late) != 0 {
		t.Fatalf("expiries made at now are not older than now: %v", ids(late))
	}
	late, err := store.ExpiriesToAudit(ctx, now.Add(time.Second), 10)
	if err != nil || len(late) != 3 {
		t.Fatalf("to audit: %v %v, want 3", late, err)
	}
	if err := store.MarkExpiryAudited(ctx, run+"due_active"); err != nil {
		t.Fatal(err)
	}
	late, _ = store.ExpiriesToAudit(ctx, now.Add(time.Second), 10)
	got := ids(late)
	sort.Strings(got)
	if fmt.Sprint(got) != "[due_later due_pending]" {
		t.Fatalf("to audit after one is marked: %v", got)
	}
}

func TestInMemoryStore_ExpiryContract(t *testing.T) {
	expiryContract(t, infrastructure.NewInMemoryStore(), "")
}

func TestPostgresStore_ExpiryContract(t *testing.T) {
	db := testDB(t)
	// ExpireDue reads the whole table: start from an empty one.
	if _, err := db.Exec(`TRUNCATE sessions`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`TRUNCATE sessions`) })
	expiryContract(t, infrastructure.NewPostgresStore(db), uniqueID("exp")+"_")
}

// Two replicas sweeping the same rows together: each session expired by exactly one.
func TestPostgresStore_ExpireDue_TwoReplicasExpireEachSessionOnce(t *testing.T) {
	db := testDB(t)
	if _, err := db.Exec(`TRUNCATE sessions`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`TRUNCATE sessions`) })
	ctx := context.Background()
	now := time.Now().UTC()
	const n = 300
	store := infrastructure.NewPostgresStore(db)
	for i := 0; i < n; i++ {
		if err := store.Save(ctx, &domain.Session{ID: fmt.Sprintf("race_%03d", i), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "u",
			PrivilegedAccountID: "acc", Justification: "j", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	other, err := infrastructure.OpenPostgres(ctx, testDSN(t))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	replicas := []domain.SessionRepository{store, infrastructure.NewPostgresStore(other)}
	var mu sync.Mutex
	seen := map[string]int{}
	var wg sync.WaitGroup
	for _, r := range replicas {
		for w := 0; w < 4; w++ {
			wg.Add(1)
			go func(r domain.SessionRepository) {
				defer wg.Done()
				for {
					due, err := r.ExpireDue(ctx, now, 7)
					if err != nil {
						t.Error(err)
						return
					}
					mu.Lock()
					for _, s := range due {
						seen[s.ID]++
					}
					mu.Unlock()
					if len(due) == 0 {
						return
					}
				}
			}(r)
		}
	}
	wg.Wait()
	if len(seen) != n {
		t.Fatalf("%d sessions expired, want %d", len(seen), n)
	}
	for id, c := range seen {
		if c != 1 {
			t.Fatalf("%s expired %d times", id, c)
		}
	}
}

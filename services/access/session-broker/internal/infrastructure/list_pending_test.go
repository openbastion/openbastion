package infrastructure_test

// ListPending (ADR-0012) has one contract and two stores: the same assertions run
// against the in-memory store and, when a database is there, PostgreSQL.

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func listPendingContract(t *testing.T, store domain.SessionRepository, prefix string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond) // PostgreSQL TIMESTAMPTZ precision

	row := func(id string, status domain.SessionStatus, expires time.Time) *domain.Session {
		return &domain.Session{
			ID: prefix + id, Status: status, Protocol: "ssh", RequestedBy: "oncall",
			PrivilegedAccountID: "acc-" + id, Justification: "recorder down during P1 INC-" + id, BreakGlass: true,
			CreatedAt: now.Add(-time.Minute), ExpiresAt: expires, DurationMinutes: 20,
		}
	}
	for _, s := range []*domain.Session{
		row("c", domain.StatusPendingApproval, now.Add(10*time.Minute)),
		row("b", domain.StatusPendingApproval, now.Add(5*time.Minute)), // same deadline as "a": the id breaks the tie
		row("a", domain.StatusPendingApproval, now.Add(5*time.Minute)),
		row("edge", domain.StatusPendingApproval, now),                        // its deadline is this very instant
		row("late", domain.StatusPendingApproval, now.Add(-time.Microsecond)), // a moment past it
		row("gone", domain.StatusPendingApproval, now.Add(-time.Hour)),
		row("active", domain.StatusActive, now.Add(time.Hour)),
		row("denied", domain.StatusDenied, now.Add(time.Hour)),
		row("terminated", domain.StatusTerminated, now.Add(time.Hour)),
		row("expired", domain.StatusExpired, now.Add(time.Hour)),
	} {
		if err := store.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}

	got, more, err := store.ListPending(ctx, now, 100)
	if err != nil {
		t.Fatal(err)
	}
	// Pending and not past their deadline; the soonest deadline first, an equal one by
	// id. "edge" is listed: at its deadline a request is still pending for
	// Session.EffectiveStatus, so the list and the decision agree on it.
	var ids []string
	for _, s := range got {
		if len(s.ID) >= len(prefix) && s.ID[:len(prefix)] == prefix {
			ids = append(ids, s.ID[len(prefix):])
		}
	}
	want := []string{"edge", "a", "b", "c"}
	if len(ids) != len(want) || more {
		t.Fatalf("listed %v (more=%v), want %v", ids, more, want)
	}
	for i := range want {
		if ids[i] != want[i] {
			t.Fatalf("listed %v, want %v in that order", ids, want)
		}
	}

	// A listed row is the whole request: the approver decides on it.
	for _, s := range got {
		if s.ID == prefix+"a" {
			if s.RequestedBy != "oncall" || s.PrivilegedAccountID != "acc-a" || s.Justification != "recorder down during P1 INC-a" ||
				!s.BreakGlass || s.DurationMinutes != 20 || s.Protocol != "ssh" || s.Status != domain.StatusPendingApproval ||
				!s.ExpiresAt.Equal(now.Add(5*time.Minute)) {
				t.Fatalf("a listed request is incomplete: %+v", s)
			}
		}
	}
}

// The bound: limit rows come back, and `more` is how the caller learns there were
// others — an exact fit is not "more".
func listPendingLimit(t *testing.T, store domain.SessionRepository, prefix string) {
	t.Helper()
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	for i, id := range []string{"x1", "x2", "x3"} {
		err := store.Save(ctx, &domain.Session{
			ID: prefix + id, Status: domain.StatusPendingApproval, Protocol: "ssh", RequestedBy: "oncall", PrivilegedAccountID: "acc",
			Justification: "recorder down", BreakGlass: true, CreatedAt: now, ExpiresAt: now.Add(time.Duration(i+1) * time.Hour), DurationMinutes: 20,
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for _, c := range []struct {
		limit    int
		wantLen  int
		wantMore bool
	}{{2, 2, true}, {3, 3, false}, {4, 3, false}, {1, 1, true}, {0, 0, true}} {
		got, more, err := store.ListPending(ctx, now, c.limit)
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != c.wantLen || more != c.wantMore {
			t.Fatalf("limit %d: %d rows, more=%v; want %d, %v", c.limit, len(got), more, c.wantLen, c.wantMore)
		}
	}
	if got, _, _ := store.ListPending(ctx, now, 2); got[0].ID != prefix+"x1" || got[1].ID != prefix+"x2" {
		t.Fatalf("the bound must cut the latest deadlines, not the soonest: %s %s", got[0].ID, got[1].ID)
	}
}

func TestInMemoryStore_ListPending_IsThePendingRequestsSoonestFirst(t *testing.T) {
	listPendingContract(t, infrastructure.NewInMemoryStore(), "m-")
}

func TestInMemoryStore_ListPending_IsBounded_AndSaysWhenItCut(t *testing.T) {
	listPendingLimit(t, infrastructure.NewInMemoryStore(), "m-")
}

func TestInMemoryStore_ListPending_ReturnsCopies(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	req := pendingRequest("s-copy")
	if err := store.Save(ctx, req); err != nil {
		t.Fatal(err)
	}
	got, _, _ := store.ListPending(ctx, time.Now(), 10)
	got[0].Status = domain.StatusActive // a caller that edits what it was given...
	if again, _ := store.Get(ctx, "s-copy"); again.Status != domain.StatusPendingApproval {
		t.Fatal("...must not edit the store")
	}
}

func TestPostgresStore_ListPending_IsThePendingRequestsSoonestFirst(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	clearPending(t, db)
	listPendingContract(t, store, uniqueID("lp")+"-")
}

func TestPostgresStore_ListPending_IsBounded_AndSaysWhenItCut(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	clearPending(t, db)
	listPendingLimit(t, store, uniqueID("lp")+"-")
}

// A database made before the partial index existed gets it from the next start, and
// the statement can be repeated.
func TestPostgresStore_ThePendingIndexIsCreatedOnAnExistingDatabase_AndIdempotently(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `DROP INDEX IF EXISTS sessions_pending_approval_idx`); err != nil {
		t.Fatal(err)
	}
	// A deployment that old predates versioned migrations too (ADR-0030): it has no row in
	// schema_migrations, so the next start runs 001_init.sql, which brings it up to date.
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE component = 'session-broker'`); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // twice: a restart is not an error
		db2, err := infrastructure.OpenPostgres(ctx, testDSN(t))
		if err != nil {
			t.Fatalf("OpenPostgres #%d: %v", i+1, err)
		}
		db2.Close()
	}
	var def string
	if err := db.QueryRowContext(ctx, `SELECT indexdef FROM pg_indexes WHERE indexname = 'sessions_pending_approval_idx'`).Scan(&def); err != nil {
		t.Fatalf("the index is missing after the upgrade: %v", err)
	}
	if !containsAll(def, "expires_at", "pending_approval") {
		t.Fatalf("the index is not the partial one on pending requests: %s", def)
	}
}

func testDSN(t *testing.T) string {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	return dsn
}

func containsAll(s string, parts ...string) bool {
	for _, p := range parts {
		if !strings.Contains(s, p) {
			return false
		}
	}
	return true
}

// clearPending removes the requests that other tests of this package left waiting in
// the shared test database: the listing is of ALL pending rows, so a test of it has to
// start from none. (The rows are test data; nothing else reads them.)
func clearPending(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM sessions WHERE status = 'pending_approval'`); err != nil {
		t.Fatal(err)
	}
}

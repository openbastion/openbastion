// The same behavioural contract is run against the in-memory store always,
// and against PostgreSQL when TEST_DATABASE_URL is set (skipped, not
// failed, otherwise — see /NOTES_SANDBOX.md). One contract for both means
// the dev/test store cannot quietly drift from the real one.
package infrastructure_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	db, err := infrastructure.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

// uniqueID keeps tests independent of each other and of earlier runs: they
// never truncate the shared table, they just use session ids nobody else has.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func cmds(entries []domain.CommandEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Command)
	}
	return out
}

func same(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func runRepositoryContract(t *testing.T, repo domain.CommandRepository) {
	ctx := context.Background()
	t0 := time.Now().UTC().Truncate(time.Microsecond) // PostgreSQL TIMESTAMPTZ precision

	t.Run("orders by timestamp then insertion, whatever the insertion order", func(t *testing.T) {
		s := uniqueID("order")
		err := repo.AppendBatch(ctx, []domain.CommandEntry{
			{SessionID: s, Timestamp: t0.Add(time.Second), Command: "third"},
			{SessionID: s, Timestamp: t0, Command: "first-a"},
			{SessionID: s, Timestamp: t0, Command: "first-b"},
		})
		if err != nil {
			t.Fatalf("AppendBatch: %v", err)
		}
		got, total, err := repo.ListBySession(ctx, s, 1, 10)
		if err != nil {
			t.Fatalf("ListBySession: %v", err)
		}
		if want := []string{"first-a", "first-b", "third"}; total != 3 || !same(cmds(got), want) {
			t.Fatalf("want %q (total 3), got %q (total %d)", want, cmds(got), total)
		}
	})

	t.Run("batches appended separately keep their order", func(t *testing.T) {
		s := uniqueID("batches")
		for i := 0; i < 3; i++ {
			if err := repo.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: t0, Command: fmt.Sprintf("c%d", i)}}); err != nil {
				t.Fatalf("AppendBatch: %v", err)
			}
		}
		got, _, _ := repo.ListBySession(ctx, s, 1, 10)
		if want := []string{"c0", "c1", "c2"}; !same(cmds(got), want) {
			t.Fatalf("want %q, got %q", want, cmds(got))
		}
	})

	t.Run("paginates with the real total", func(t *testing.T) {
		s := uniqueID("pages")
		var batch []domain.CommandEntry
		for i := 0; i < 7; i++ {
			batch = append(batch, domain.CommandEntry{SessionID: s, Timestamp: t0.Add(time.Duration(i) * time.Second), Command: fmt.Sprintf("c%d", i)})
		}
		_ = repo.AppendBatch(ctx, batch)

		p2, total, _ := repo.ListBySession(ctx, s, 2, 3)
		if total != 7 || !same(cmds(p2), []string{"c3", "c4", "c5"}) {
			t.Fatalf("page 2 of 3: total=%d %q", total, cmds(p2))
		}
		p3, _, _ := repo.ListBySession(ctx, s, 3, 3)
		if !same(cmds(p3), []string{"c6"}) {
			t.Fatalf("page 3 of 3: %q", cmds(p3))
		}
		past, total, _ := repo.ListBySession(ctx, s, 9, 3)
		if len(past) != 0 || total != 7 {
			t.Fatalf("past the end: %d entries, total %d", len(past), total)
		}
	})

	t.Run("sessions are isolated", func(t *testing.T) {
		a, b := uniqueID("iso-a"), uniqueID("iso-b")
		_ = repo.AppendBatch(ctx, []domain.CommandEntry{
			{SessionID: a, Timestamp: t0, Command: "in-a"},
			{SessionID: b, Timestamp: t0, Command: "in-b"},
		})
		got, total, _ := repo.ListBySession(ctx, a, 1, 10)
		if total != 1 || !same(cmds(got), []string{"in-a"}) {
			t.Fatalf("session a: %q (total %d)", cmds(got), total)
		}
	})

	t.Run("an unknown session is an empty, non-nil page", func(t *testing.T) {
		got, total, err := repo.ListBySession(ctx, uniqueID("nobody"), 1, 10)
		if err != nil || total != 0 || got == nil || len(got) != 0 {
			t.Fatalf("got %v total=%d err=%v", got, total, err)
		}
	})

	t.Run("round-trips text and timestamps exactly", func(t *testing.T) {
		s := uniqueID("text")
		in := domain.CommandEntry{SessionID: s, Timestamp: t0, Command: "echo 'héllo' ✓ \"quoted\" \\ back; ls | wc -l"}
		_ = repo.AppendBatch(ctx, []domain.CommandEntry{in})
		got, _, _ := repo.ListBySession(ctx, s, 1, 10)
		if len(got) != 1 || got[0].Command != in.Command || !got[0].Timestamp.Equal(t0) || got[0].SessionID != s || got[0].ID == 0 {
			t.Fatalf("round trip differs: %+v", got)
		}
	})
}

func TestInMemoryStore_Contract(t *testing.T) {
	runRepositoryContract(t, infrastructure.NewInMemoryStore())
}

func TestPostgresStore_Contract(t *testing.T) {
	runRepositoryContract(t, infrastructure.NewPostgresStore(testDB(t)))
}

// A batch is all-or-nothing in PostgreSQL: PostgreSQL TEXT refuses a NUL
// byte, so a batch containing one fails — and the entries before it must not
// have been kept. (RecorderService strips NULs before they get this far;
// this proves the store's own atomicity, which is what protects a batch from
// any OTHER failure part-way through.)
func TestPostgresStore_AppendBatchIsAtomic(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	s := uniqueID("atomic")
	now := time.Now().UTC()

	err := store.AppendBatch(ctx, []domain.CommandEntry{
		{SessionID: s, Timestamp: now, Command: "kept-if-not-atomic"},
		{SessionID: s, Timestamp: now, Command: "bad\x00nul"},
	})
	if err == nil {
		t.Fatal("expected PostgreSQL to refuse the NUL byte")
	}
	got, total, _ := store.ListBySession(ctx, s, 1, 10)
	if total != 0 || len(got) != 0 {
		t.Fatalf("part of a failed batch was committed: %q", cmds(got))
	}
}

// Two stores on two connections see the same data — what the restart
// integration test relies on, proven here without starting processes.
func TestPostgresStore_EntriesAreVisibleToAnotherConnection(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	ctx := context.Background()
	s := uniqueID("reopen")
	db1, err := infrastructure.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	_ = infrastructure.NewPostgresStore(db1).AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: time.Now().UTC(), Command: "survives"}})
	db1.Close()

	db2, err := infrastructure.OpenPostgres(ctx, dsn) // also re-applies the (idempotent) migration
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	got, total, _ := infrastructure.NewPostgresStore(db2).ListBySession(ctx, s, 1, 10)
	if total != 1 || !same(cmds(got), []string{"survives"}) {
		t.Fatalf("got %q (total %d)", cmds(got), total)
	}
}

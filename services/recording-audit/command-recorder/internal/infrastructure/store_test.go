// The same behavioural contract is run against the in-memory store always,
// and against PostgreSQL when TEST_DATABASE_URL is set (skipped, not
// failed, otherwise — see /NOTES_SANDBOX.md). One contract for both means
// the dev/test store cannot quietly drift from the real one.
package infrastructure_test

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
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

var (
	kekHexA = strings.Repeat("ab", 32)
	kekHexB = strings.Repeat("cd", 32)
)

func testKEK(t *testing.T, hexKey string) infrastructure.KeyWrapper {
	t.Helper()
	kek, err := infrastructure.NewLocalKEKFromHexKey(hexKey)
	if err != nil {
		t.Fatalf("NewLocalKEKFromHexKey: %v", err)
	}
	return kek
}

func testPostgresStore(t *testing.T, db *sql.DB, hexKey string) *infrastructure.PostgresStore {
	t.Helper()
	store, err := infrastructure.NewPostgresStore(context.Background(), db, testKEK(t, hexKey))
	if err != nil {
		t.Fatalf("NewPostgresStore: %v", err)
	}
	return store
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

// The very same contract as the in-memory store, with encryption in the
// path: sealing must be invisible to everything above the store.
func TestPostgresStore_Contract(t *testing.T) {
	runRepositoryContract(t, testPostgresStore(t, testDB(t), kekHexA))
}

// A batch is all-or-nothing in PostgreSQL. A command can no longer be used to
// force a failure — it is sealed into BYTEA, which accepts anything — but a
// session id is still a TEXT column, and PostgreSQL TEXT refuses a NUL byte.
// The failing entry comes AFTER a valid one in the same batch, so if the batch
// were not atomic the valid entry, and the session's new key, would remain.
// (RecorderService refuses such a session id before it gets this far; this
// proves the store's own atomicity, which protects a batch from any OTHER
// failure part-way through.)
func TestPostgresStore_AppendBatchIsAtomic(t *testing.T) {
	db := testDB(t)
	store := testPostgresStore(t, db, kekHexA)
	ctx := context.Background()
	s := uniqueID("atomic")
	now := time.Now().UTC()

	err := store.AppendBatch(ctx, []domain.CommandEntry{
		{SessionID: s, Timestamp: now, Command: "kept-if-not-atomic"},
		{SessionID: s + "\x00bad", Timestamp: now, Command: "refused"},
	})
	if err == nil {
		t.Fatal("expected PostgreSQL to refuse the NUL byte in the session id")
	}
	got, total, _ := store.ListBySession(ctx, s, 1, 10)
	if total != 0 || len(got) != 0 {
		t.Fatalf("part of a failed batch was committed: %q", cmds(got))
	}
	var keys int
	_ = db.QueryRow(`SELECT count(*) FROM session_recording_keys WHERE session_id = $1`, s).Scan(&keys)
	if keys != 0 {
		t.Fatalf("the key created for a failed batch was committed (%d key rows)", keys)
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
	_ = testPostgresStore(t, db1, kekHexA).AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: time.Now().UTC(), Command: "survives"}})
	db1.Close()

	db2, err := infrastructure.OpenPostgres(ctx, dsn) // also re-applies the (idempotent) migration
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	got, total, _ := testPostgresStore(t, db2, kekHexA).ListBySession(ctx, s, 1, 10)
	if total != 1 || !same(cmds(got), []string{"survives"}) {
		t.Fatalf("got %q (total %d)", cmds(got), total)
	}
}

// -- encryption at rest ------------------------------------------------------

// The point of the whole feature, asserted against the raw tables rather than
// through the store: nothing the operator typed is readable in the database.
func TestPostgresStore_NothingIsStoredInTheClear(t *testing.T) {
	db := testDB(t)
	store := testPostgresStore(t, db, kekHexA)
	ctx := context.Background()
	s := uniqueID("clear")
	marker := "TOP-SECRET-MARKER-" + s
	now := time.Now().UTC()

	if err := store.AppendBatch(ctx, []domain.CommandEntry{
		{SessionID: s, Timestamp: now, Command: "mysql -p" + marker},
		{SessionID: s, Timestamp: now.Add(time.Second), Command: "mysql -p" + marker}, // identical text
	}); err != nil {
		t.Fatalf("AppendBatch: %v", err)
	}

	rows, err := db.Query(`SELECT command_sealed FROM session_command_entries WHERE session_id = $1 ORDER BY id`, s)
	if err != nil {
		t.Fatal(err)
	}
	var sealed [][]byte
	for rows.Next() {
		var b []byte
		_ = rows.Scan(&b)
		sealed = append(sealed, b)
	}
	rows.Close()
	if len(sealed) != 2 {
		t.Fatalf("expected 2 stored rows, got %d", len(sealed))
	}
	for _, b := range sealed {
		if bytes.Contains(b, []byte(marker)) || bytes.Contains(b, []byte("mysql")) {
			t.Fatalf("a stored command is readable in the database: %q", b)
		}
	}
	if bytes.Equal(sealed[0], sealed[1]) {
		t.Fatal("two identical commands must not produce identical stored bytes")
	}

	var wrapped []byte
	if err := db.QueryRow(`SELECT wrapped_dek FROM session_recording_keys WHERE session_id = $1`, s).Scan(&wrapped); err != nil {
		t.Fatalf("no stored key for the session: %v", err)
	}
	if len(wrapped) <= 32 {
		t.Fatalf("the stored key (%d bytes) is not a wrapped key — it is the size of a raw one", len(wrapped))
	}

	var plaintextColumns int
	_ = db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'session_command_entries' AND column_name = 'command'`).Scan(&plaintextColumns)
	if plaintextColumns != 0 {
		t.Fatal("the table still has a plaintext `command` column")
	}

	got, _, _ := store.ListBySession(ctx, s, 1, 10)
	if len(got) != 2 || got[0].Command != "mysql -p"+marker {
		t.Fatalf("the store must still return the plaintext: %q", cmds(got))
	}
}

func TestPostgresStore_EachSessionHasItsOwnKey(t *testing.T) {
	db := testDB(t)
	store := testPostgresStore(t, db, kekHexA)
	ctx := context.Background()
	a, b := uniqueID("key-a"), uniqueID("key-b")
	now := time.Now().UTC()

	for i := 0; i < 3; i++ { // several batches for the same session reuse its one key
		_ = store.AppendBatch(ctx, []domain.CommandEntry{
			{SessionID: a, Timestamp: now, Command: fmt.Sprintf("a%d", i)},
			{SessionID: b, Timestamp: now, Command: fmt.Sprintf("b%d", i)},
		})
	}
	var rowsA, rowsB int
	_ = db.QueryRow(`SELECT count(*) FROM session_recording_keys WHERE session_id = $1`, a).Scan(&rowsA)
	_ = db.QueryRow(`SELECT count(*) FROM session_recording_keys WHERE session_id = $1`, b).Scan(&rowsB)
	if rowsA != 1 || rowsB != 1 {
		t.Fatalf("expected exactly one key row per session, got %d and %d", rowsA, rowsB)
	}
	var wa, wb []byte
	_ = db.QueryRow(`SELECT wrapped_dek FROM session_recording_keys WHERE session_id = $1`, a).Scan(&wa)
	_ = db.QueryRow(`SELECT wrapped_dek FROM session_recording_keys WHERE session_id = $1`, b).Scan(&wb)
	if bytes.Equal(wa, wb) {
		t.Fatal("two sessions share a wrapped key")
	}
}

// Two recorders (or two batches) meeting a brand-new session at the same moment
// must end up with ONE key — otherwise the loser's entries would be sealed under
// a key that was never stored, and unreadable.
func TestPostgresStore_ConcurrentBatchesForANewSessionShareOneKey(t *testing.T) {
	db := testDB(t)
	store := testPostgresStore(t, db, kekHexA)
	ctx := context.Background()
	s := uniqueID("race")
	now := time.Now().UTC()

	const writers = 8
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			errs <- store.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: now.Add(time.Duration(i) * time.Millisecond), Command: fmt.Sprintf("w%d", i)}})
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("a concurrent AppendBatch failed: %v", err)
		}
	}

	var keys int
	_ = db.QueryRow(`SELECT count(*) FROM session_recording_keys WHERE session_id = $1`, s).Scan(&keys)
	if keys != 1 {
		t.Fatalf("expected one key for the session, got %d", keys)
	}
	got, total, err := store.ListBySession(ctx, s, 1, 100)
	if err != nil || total != writers || len(got) != writers {
		t.Fatalf("every concurrent entry must be readable: total=%d len=%d err=%v", total, len(got), err)
	}
}

// A database-level attacker edits a stored row. Reading must FAIL — a replay
// with an altered or silently missing line is worse than none — and must not
// reveal anything.
func TestPostgresStore_AlteredRowsAreDetected(t *testing.T) {
	db := testDB(t)
	store := testPostgresStore(t, db, kekHexA)
	ctx := context.Background()
	now := time.Now().UTC()

	tampers := map[string]func(t *testing.T, victim, other string){
		"a flipped ciphertext byte": func(t *testing.T, victim, other string) {
			_, err := db.Exec(`UPDATE session_command_entries SET command_sealed = set_byte(command_sealed, 20, get_byte(command_sealed, 20) # 1) WHERE session_id = $1`, victim)
			must(t, err)
		},
		"an edited timestamp": func(t *testing.T, victim, other string) {
			_, err := db.Exec(`UPDATE session_command_entries SET ts = ts + interval '1 second' WHERE session_id = $1`, victim)
			must(t, err)
		},
		"a row moved to another session": func(t *testing.T, victim, other string) {
			_, err := db.Exec(`UPDATE session_command_entries SET session_id = $1 WHERE session_id = $2`, other, victim)
			must(t, err)
		},
		"another session's wrapped key swapped in": func(t *testing.T, victim, other string) {
			_, err := db.Exec(`UPDATE session_recording_keys SET wrapped_dek = (SELECT wrapped_dek FROM session_recording_keys WHERE session_id = $1) WHERE session_id = $2`, other, victim)
			must(t, err)
		},
	}
	for name, tamper := range tampers {
		t.Run(name, func(t *testing.T) {
			victim, other := uniqueID("tamper-v"), uniqueID("tamper-o")
			marker := "ALTERED-MARKER-" + victim
			must(t, store.AppendBatch(ctx, []domain.CommandEntry{
				{SessionID: victim, Timestamp: now, Command: marker},
				{SessionID: other, Timestamp: now, Command: "legit"},
			}))
			tamper(t, victim, other)

			// "a row moved" is read back as the OTHER session; the rest as the victim.
			readAs := victim
			if strings.Contains(name, "moved") {
				readAs = other
			}
			got, _, err := store.ListBySession(ctx, readAs, 1, 10)
			if err == nil {
				t.Fatalf("the altered recording was served: %q", cmds(got))
			}
			if strings.Contains(err.Error(), marker) {
				t.Fatalf("the error leaks recording content: %v", err)
			}
		})
	}
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

// Without the right KEK the database is useless — including to a recorder
// started with the wrong key by mistake, which must fail rather than return
// garbage or quietly start a second key for the same session.
func TestPostgresStore_AnotherKEKCannotReadOrExtendARecording(t *testing.T) {
	db := testDB(t)
	right := testPostgresStore(t, db, kekHexA)
	wrong := testPostgresStore(t, db, kekHexB)
	ctx := context.Background()
	s := uniqueID("kek")
	now := time.Now().UTC()
	must(t, right.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: now, Command: "private"}}))

	if got, _, err := wrong.ListBySession(ctx, s, 1, 10); err == nil {
		t.Fatalf("a different KEK read the recording: %q", cmds(got))
	}
	if err := wrong.AppendBatch(ctx, []domain.CommandEntry{{SessionID: s, Timestamp: now, Command: "more"}}); err == nil {
		t.Fatal("a different KEK appended to an existing recording")
	}
	got, total, err := right.ListBySession(ctx, s, 1, 10)
	if err != nil || total != 1 || got[0].Command != "private" {
		t.Fatalf("the right KEK must be unaffected: %q total=%d err=%v", cmds(got), total, err)
	}
}

// A database created before encryption existed holds plaintext rows. Opening
// the store must seal them and remove the plaintext column — otherwise
// "nothing is stored in the clear" would be true only for new data. Runs in
// its own schema so it cannot disturb the shared table.
func TestPostgresStore_SealsRowsStoredBeforeEncryptionExisted(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	ctx := context.Background()
	schema := fmt.Sprintf("recorder_upgrade_%d", time.Now().UnixNano())

	admin, err := sql.Open("postgres", dsn)
	must(t, err)
	defer admin.Close()
	_, err = admin.Exec(`CREATE SCHEMA ` + schema)
	must(t, err)
	defer admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`)

	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	scoped := dsn + sep + "search_path=" + schema

	// The pre-encryption table, exactly as the first version of this service created it.
	legacy, err := sql.Open("postgres", scoped)
	must(t, err)
	_, err = legacy.Exec(`CREATE TABLE session_command_entries (
		id BIGSERIAL PRIMARY KEY, session_id TEXT NOT NULL, ts TIMESTAMPTZ NOT NULL, command TEXT NOT NULL)`)
	must(t, err)
	t0 := time.Now().UTC().Truncate(time.Microsecond)
	for i, row := range []struct{ session, command string }{
		{"old-session-1", "legacy-command-one"}, {"old-session-2", "legacy-command-two"}, {"old-session-1", "legacy-command-three"},
	} {
		_, err = legacy.Exec(`INSERT INTO session_command_entries (session_id, ts, command) VALUES ($1, $2, $3)`,
			row.session, t0.Add(time.Duration(i)*time.Second), row.command)
		must(t, err)
	}
	legacy.Close()

	db, err := infrastructure.OpenPostgres(ctx, scoped)
	must(t, err)
	defer db.Close()
	store := testPostgresStore(t, db, kekHexA)

	got, total, err := store.ListBySession(ctx, "old-session-1", 1, 10)
	if err != nil || total != 2 || !same(cmds(got), []string{"legacy-command-one", "legacy-command-three"}) {
		t.Fatalf("old rows must survive the upgrade, in order: %q total=%d err=%v", cmds(got), total, err)
	}

	var plaintextColumns int
	_ = db.QueryRow(`SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'session_command_entries' AND column_name = 'command'`, schema).Scan(&plaintextColumns)
	if plaintextColumns != 0 {
		t.Fatal("the plaintext column was not dropped")
	}
	var leaked int
	_ = db.QueryRow(`SELECT count(*) FROM session_command_entries WHERE position('legacy-command'::bytea in command_sealed) > 0`).Scan(&leaked)
	if leaked != 0 {
		t.Fatal("an old command is still readable in the database")
	}
	var keys int
	_ = db.QueryRow(`SELECT count(*) FROM session_recording_keys`).Scan(&keys)
	if keys != 2 {
		t.Fatalf("expected one key per old session (2), got %d", keys)
	}

	// Idempotent: a second start (another replica, a restart) finds nothing to do.
	if _, err := infrastructure.NewPostgresStore(ctx, db, testKEK(t, kekHexA)); err != nil {
		t.Fatalf("second NewPostgresStore: %v", err)
	}
	if got, _, err := store.ListBySession(ctx, "old-session-2", 1, 10); err != nil || len(got) != 1 || got[0].Command != "legacy-command-two" {
		t.Fatalf("after a second start: %q, %v", cmds(got), err)
	}
}

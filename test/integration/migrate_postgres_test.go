package integration_test

// pkg/migrate against a real PostgreSQL (ADR-0030): under a lock, once, in a transaction,
// and never a migration whose text changed after it was applied.

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/openbastion/openbastion/pkg/migrate"
)

func migrateDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// forget removes what a test component left: its tables and its rows in schema_migrations.
func forget(t *testing.T, db *sql.DB, component string, tables ...string) {
	t.Helper()
	for _, tbl := range tables {
		if _, err := db.Exec(`DROP TABLE IF EXISTS ` + tbl + ` CASCADE`); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN
		DELETE FROM schema_migrations WHERE component = '` + component + `'; END IF; END $$`); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresMigrate_ConcurrentAppliersOnAFreshDatabase_NoneFails(t *testing.T) {
	db := migrateDB(t)
	const component, rounds, appliers = "test-migrate-race", 20, 8
	files := fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE IF NOT EXISTS mig_race_a (id TEXT PRIMARY KEY, n INTEGER NOT NULL);
			CREATE INDEX IF NOT EXISTS mig_race_a_n ON mig_race_a (n);`)},
		"002_more.sql": {Data: []byte(`CREATE TABLE IF NOT EXISTS mig_race_b (id TEXT PRIMARY KEY);`)},
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	t.Cleanup(func() { forget(t, db, component, "mig_race_a", "mig_race_b") })

	failures := 0
	for round := 0; round < rounds; round++ {
		forget(t, db, component, "mig_race_a", "mig_race_b")
		var wg sync.WaitGroup
		errs := make(chan error, appliers)
		start := make(chan struct{})
		pools := make([]*sql.DB, 0, appliers)
		for i := 0; i < appliers; i++ {
			own, err := sql.Open("postgres", dsn) // one pool each, as separate replicas have
			if err != nil {
				t.Fatal(err)
			}
			pools = append(pools, own)
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := migrate.Apply(context.Background(), own, component, files)
				errs <- err
			}()
		}
		close(start)
		wg.Wait()
		for _, p := range pools {
			p.Close()
		}
		close(errs)
		for err := range errs {
			if err != nil {
				failures++
				t.Logf("round %d: %v", round, err)
			}
		}
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE component = $1`, component).Scan(&n)
		if n != 2 {
			t.Fatalf("round %d: %d rows recorded, want 2 — each version exactly once", round, n)
		}
	}
	if failures != 0 {
		t.Fatalf("%d of %d concurrent appliers failed", failures, rounds*appliers)
	}
}

func TestPostgresMigrate_EachMigrationIsAppliedOnce(t *testing.T) {
	db := migrateDB(t)
	const component = "test-migrate-once"
	forget(t, db, component, "mig_once")
	t.Cleanup(func() { forget(t, db, component, "mig_once") })
	files := fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE mig_once (n INTEGER NOT NULL);`)},
		"002_seed.sql": {Data: []byte(`INSERT INTO mig_once (n) VALUES (1);`)},
	}
	for i, want := range []string{"[1 2]", "[]", "[]"} {
		res, err := migrate.Apply(context.Background(), db, component, files)
		if err != nil {
			t.Fatalf("pass %d: %v", i, err)
		}
		if got := fmt.Sprint(res.Applied); got != want && !(want == "[]" && res.Applied == nil) {
			t.Fatalf("pass %d applied %v, want %s", i, res.Applied, want)
		}
		if res.Current != 2 {
			t.Fatalf("pass %d: current %d, want 2", i, res.Current)
		}
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM mig_once`).Scan(&n)
	if n != 1 {
		t.Fatalf("%d rows seeded after three passes, want 1 — a migration runs once", n)
	}
	// The lock is released when Apply returns: another session takes it at once.
	other, err := sql.Open("postgres", os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	var got bool
	if err := other.QueryRow(`SELECT pg_try_advisory_lock($1)`, migrate.LockKey(component)).Scan(&got); err != nil || !got {
		t.Fatalf("the migration lock is still held after Apply returned (%v)", err)
	}
}

func TestPostgresMigrate_ComponentsCreatingTheTableTogether_NoneFails(t *testing.T) {
	db := migrateDB(t)
	dsn := os.Getenv("TEST_DATABASE_URL")
	const rounds, components = 10, 6
	failures := 0
	for round := 0; round < rounds; round++ {
		// No schema_migrations yet: every component creates it at once. The services
		// recreate it and record their 001_init.sql again at their next start (it is
		// idempotent): this costs the tests nothing.
		if _, err := db.Exec(`DROP TABLE IF EXISTS schema_migrations`); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		errs := make(chan error, components)
		start := make(chan struct{})
		pools := make([]*sql.DB, 0, components)
		for i := 0; i < components; i++ {
			own, err := sql.Open("postgres", dsn)
			if err != nil {
				t.Fatal(err)
			}
			pools = append(pools, own)
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				<-start
				_, err := migrate.Apply(context.Background(), own, fmt.Sprintf("test-migrate-table-%d", i),
					fstest.MapFS{"001_init.sql": {Data: []byte(`SELECT 1;`)}})
				errs <- err
			}(i)
		}
		close(start)
		wg.Wait()
		for _, p := range pools {
			p.Close()
		}
		close(errs)
		for err := range errs {
			if err != nil {
				failures++
				t.Logf("round %d: %v", round, err)
			}
		}
	}
	_, _ = db.Exec(`DELETE FROM schema_migrations WHERE component LIKE 'test-migrate-table-%'`)
	if failures != 0 {
		t.Fatalf("%d of %d components creating schema_migrations together failed", failures, rounds*components)
	}
}

func TestPostgresMigrate_AMigrationChangedAfterItWasAppliedIsRefused(t *testing.T) {
	db := migrateDB(t)
	const component = "test-migrate-changed"
	forget(t, db, component, "mig_changed", "mig_changed_later")
	t.Cleanup(func() { forget(t, db, component, "mig_changed", "mig_changed_later") })
	if _, err := migrate.Apply(context.Background(), db, component, fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE mig_changed (n INTEGER);`)},
	}); err != nil {
		t.Fatal(err)
	}
	for name, files := range map[string]fstest.MapFS{
		"its text changed": {
			"001_init.sql":  {Data: []byte(`CREATE TABLE mig_changed (n INTEGER, m INTEGER);`)},
			"002_later.sql": {Data: []byte(`CREATE TABLE mig_changed_later (n INTEGER);`)},
		},
		"its name changed": {
			"001_start.sql": {Data: []byte(`CREATE TABLE mig_changed (n INTEGER);`)},
			"002_later.sql": {Data: []byte(`CREATE TABLE mig_changed_later (n INTEGER);`)},
		},
	} {
		_, err := migrate.Apply(context.Background(), db, component, files)
		if err == nil || !strings.Contains(err.Error(), "changed after it was applied") || !strings.Contains(err.Error(), "001_") {
			t.Fatalf("%s: %v, want a refusal naming the migration", name, err)
		}
		var later sql.NullString
		_ = db.QueryRow(`SELECT to_regclass('mig_changed_later')::text`).Scan(&later)
		if later.Valid {
			t.Fatalf("%s: a later migration was applied after the refusal", name)
		}
	}
}

func TestPostgresMigrate_AFailedMigrationLeavesNothingAndIsNamed(t *testing.T) {
	db := migrateDB(t)
	const component = "test-migrate-failed"
	forget(t, db, component, "mig_failed_a", "mig_failed_b")
	t.Cleanup(func() { forget(t, db, component, "mig_failed_a", "mig_failed_b") })
	files := fstest.MapFS{
		"001_init.sql":   {Data: []byte(`CREATE TABLE mig_failed_a (n INTEGER);`)},
		"002_broken.sql": {Data: []byte(`CREATE TABLE mig_failed_b (n INTEGER); SELECT no_such_function();`)},
	}
	_, err := migrate.Apply(context.Background(), db, component, files)
	if err == nil || !strings.Contains(err.Error(), "002_broken.sql") {
		t.Fatalf("got %v, want an error naming 002_broken.sql", err)
	}
	var versions []int
	rows, _ := db.Query(`SELECT version FROM schema_migrations WHERE component = $1 ORDER BY version`, component)
	for rows.Next() {
		var v int
		_ = rows.Scan(&v)
		versions = append(versions, v)
	}
	rows.Close()
	if fmt.Sprint(versions) != "[1]" {
		t.Fatalf("recorded %v, want [1]: the failed migration is not recorded", versions)
	}
	var b sql.NullString
	_ = db.QueryRow(`SELECT to_regclass('mig_failed_b')::text`).Scan(&b)
	if b.Valid {
		t.Fatal("the failed migration's first statement stayed: it was not in a transaction")
	}
}

func TestPostgresMigrate_ADatabaseAheadOfTheBinaryIsSaid_AndComponentsDoNotMix(t *testing.T) {
	db := migrateDB(t)
	const a, b = "test-migrate-ahead-a", "test-migrate-ahead-b"
	forget(t, db, a, "mig_ahead_a", "mig_ahead_a3")
	forget(t, db, b, "mig_ahead_b")
	t.Cleanup(func() { forget(t, db, a, "mig_ahead_a", "mig_ahead_a3"); forget(t, db, b, "mig_ahead_b") })
	newer := fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE mig_ahead_a (n INTEGER);`)},
		"002_more.sql": {Data: []byte(`ALTER TABLE mig_ahead_a ADD COLUMN m INTEGER;`)},
		"003_last.sql": {Data: []byte(`CREATE TABLE mig_ahead_a3 (n INTEGER);`)},
	}
	if _, err := migrate.Apply(context.Background(), db, a, newer); err != nil {
		t.Fatal(err)
	}
	older := fstest.MapFS{"001_init.sql": newer["001_init.sql"], "002_more.sql": newer["002_more.sql"]}
	res, err := migrate.Apply(context.Background(), db, a, older)
	if err != nil {
		t.Fatalf("an older binary on a newer database: %v, want it to start", err)
	}
	if fmt.Sprint(res.Unknown) != "[3]" || len(res.Applied) != 0 || res.Current != 2 {
		t.Fatalf("got %+v, want version 3 reported unknown, nothing applied, current 2", res)
	}
	// Another component's version 1, with another text, is its own.
	if _, err := migrate.Apply(context.Background(), db, b, fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE mig_ahead_b (n INTEGER);`)},
	}); err != nil {
		t.Fatalf("a second component with its own version 1: %v", err)
	}
}

func TestPostgresMigrate_AMigrationAndItsRecordAreOne(t *testing.T) {
	db := migrateDB(t)
	const component = "test-migrate-atomic"
	forget(t, db, component, "mig_atomic")
	t.Cleanup(func() { forget(t, db, component, "mig_atomic") })
	// The migration succeeds, then recording it fails (its version is already taken, by the
	// migration itself): neither may stay.
	_, err := migrate.Apply(context.Background(), db, component, fstest.MapFS{
		"001_init.sql": {Data: []byte(`CREATE TABLE mig_atomic (n INTEGER);
			INSERT INTO schema_migrations (component, version, name, checksum) VALUES ('test-migrate-atomic', 1, 'squatter', '\x00');`)},
	})
	if err == nil {
		t.Fatal("recording the migration could not succeed, yet Apply did not fail")
	}
	var tbl sql.NullString
	_ = db.QueryRow(`SELECT to_regclass('mig_atomic')::text`).Scan(&tbl)
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE component = $1`, component).Scan(&n)
	if tbl.Valid || n != 0 {
		t.Fatalf("table kept: %v, rows kept: %d — a migration that is not recorded must leave nothing", tbl.Valid, n)
	}
}

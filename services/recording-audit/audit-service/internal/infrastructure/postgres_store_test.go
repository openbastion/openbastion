// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
// Mirrors services/vault/password-vault/internal/infrastructure/postgres_store_test.go
// and services/access/authorization/internal/infrastructure/postgres_store_test.go.
package infrastructure_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
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

// uniqueID avoids colliding with rows left behind by earlier runs against
// the same persistent database — audit_events.id has a UNIQUE
// constraint, exactly like policies and privileged_accounts elsewhere in
// this project.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

// Last() has no filter by design — it reads the whole table's tail
// (`ORDER BY seq DESC LIMIT 1`), matching AuditService.EmitEvent's own
// real use, which always wants the single most recent event regardless
// of who wrote it. That makes a true "empty chain" case impossible to
// assert here, since this database is shared and persistent across the
// other tests in this file — covered instead by
// TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart in
// test/integration, which starts a brand new process against a freshly
// truncated table.

func TestPostgresStore_AppendThenLast_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	before, err := store.Last(ctx)
	if err != nil {
		t.Fatalf("Last (before): %v", err)
	}
	var prevHash []byte
	if before != nil {
		prevHash = before.Hash
	}

	e := &domain.Event{
		ID: uniqueID("evt"), Timestamp: time.Now().UTC(), ActorID: "it-actor",
		Action: "session.connect", ResourceType: "session", ResourceID: uniqueID("sess"),
		Success: true, PrevHash: prevHash, Hash: []byte("fake-hash-" + uniqueID("h")),
	}
	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.Last(ctx)
	if err != nil {
		t.Fatalf("Last (after): %v", err)
	}
	if got == nil {
		t.Fatal("expected Last to return the just-appended event, got nil")
	}
	if got.ID != e.ID || got.Action != e.Action || got.ActorID != e.ActorID || string(got.Hash) != string(e.Hash) {
		t.Fatalf("unexpected round-tripped event: %+v", got)
	}
	if got.Timestamp.IsZero() {
		t.Fatal("expected Timestamp to be populated")
	}
}

func TestPostgresStore_Append_EmptyActorIDRoundTripsAsEmptyNotError(t *testing.T) {
	// A system action (Scheduler, bootstrap) has no actor — domain.Event
	// explicitly documents ActorID as "empty for a system action". The
	// column is nullable for exactly this case; this test pins that an
	// empty ActorID survives the NULL round trip as "", not as an error
	// or a literal "NULL" string.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	e := &domain.Event{
		ID: uniqueID("evt-system"), Timestamp: time.Now().UTC(), ActorID: "",
		Action: "scheduler.sweep", ResourceType: "session", ResourceID: uniqueID("sess"),
		Success: true, Hash: []byte("fake-hash-" + uniqueID("h")),
	}
	if err := store.Append(ctx, e); err != nil {
		t.Fatalf("Append: %v", err)
	}

	got, err := store.Last(ctx)
	if err != nil {
		t.Fatalf("Last: %v", err)
	}
	if got.ID != e.ID {
		t.Fatalf("expected Last to return the just-appended system event, got %+v", got)
	}
	if got.ActorID != "" {
		t.Fatalf("expected ActorID to round-trip as empty string, got %q", got.ActorID)
	}
}

func TestPostgresStore_All_ReturnsEventsInInsertionOrder(t *testing.T) {
	// All() must return rows in the order they were inserted (`seq`
	// ascending) — VerifyChain (audit_service.go) walks this slice
	// front-to-back and fails closed the moment prev_hash doesn't match
	// the preceding event, so any reordering here would make a perfectly
	// intact chain look tampered.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	run := uniqueID("chain")
	var hashes [3][]byte
	var prevHash []byte
	for i := 0; i < 3; i++ {
		hashes[i] = []byte(fmt.Sprintf("%s-hash-%d", run, i))
		e := &domain.Event{
			ID: fmt.Sprintf("%s-evt-%d", run, i), Timestamp: time.Now().UTC(),
			ActorID: "it-actor", Action: "test.append", ResourceType: "chain-test",
			ResourceID: run, Success: true, PrevHash: prevHash, Hash: hashes[i],
		}
		if err := store.Append(ctx, e); err != nil {
			t.Fatalf("Append %d: %v", i, err)
		}
		prevHash = hashes[i]
	}

	all, err := store.All(ctx)
	if err != nil {
		t.Fatalf("All: %v", err)
	}

	// Filter down to just this run's events — All() returns the whole,
	// shared, persistent table, like Last() does.
	var ours []*domain.Event
	for _, e := range all {
		if e.ResourceID == run {
			ours = append(ours, e)
		}
	}
	if len(ours) != 3 {
		t.Fatalf("expected exactly 3 events for this run, got %d", len(ours))
	}
	for i, e := range ours {
		if string(e.Hash) != string(hashes[i]) {
			t.Fatalf("event %d out of order: got hash %q, want %q — All() did not return insertion order", i, e.Hash, hashes[i])
		}
		if i > 0 && string(e.PrevHash) != string(hashes[i-1]) {
			t.Fatalf("event %d: prev_hash %q does not chain to the preceding event's hash %q", i, e.PrevHash, hashes[i-1])
		}
	}
}

// The format of an event's hash is stored with it, and read back as written (ADR-0026).
func TestPostgresStore_HashVersionRoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	for _, v := range []int{domain.HashV1, domain.HashV2} {
		e := &domain.Event{ID: uniqueID("evt-version"), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ActorID: "u",
			Action: "session.read", ResourceType: "session", ResourceID: "s", Success: true, Hash: []byte{1}, HashVersion: v}
		if err := store.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		got, err := store.Last(ctx)
		if err != nil || got.ID != e.ID || got.HashVersion != v {
			t.Fatalf("version %d: read back %+v, %v", v, got, err)
		}
	}
}

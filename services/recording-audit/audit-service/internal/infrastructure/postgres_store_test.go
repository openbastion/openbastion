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

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
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

func TestPostgresStore_EventDetailsRoundTrip(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	last, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prevHash []byte
	if last != nil {
		prevHash = last.Hash
	}
	e := &domain.Event{
		ID: uniqueID("evt-details"), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ActorID: "it-actor", PrevHash: prevHash,
		Action: "session.approval_requested", ResourceType: "session", ResourceID: uniqueID("sess"),
		Details: map[string]string{"ticket": "CHG0001234"}, Success: true, Hash: []byte{1}, HashVersion: domain.HashV4,
	}
	if err := store.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	got, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != e.ID || got.Details["ticket"] != e.Details["ticket"] {
		t.Fatalf("Last: details did not round-trip: %+v", got)
	}
	all, err := store.All(ctx)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, event := range all {
		if event.ID == e.ID {
			found = event.Details["ticket"] == "CHG0001234"
		}
	}
	if !found {
		t.Fatal("All: event details did not round-trip")
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

	last, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prevHash []byte
	if last != nil {
		prevHash = last.Hash
	}
	e := &domain.Event{
		ID: uniqueID("evt-system"), Timestamp: time.Now().UTC(), ActorID: "", PrevHash: prevHash,
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
	last, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prevHash []byte
	if last != nil {
		prevHash = last.Hash
	}
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

// The format of an event's hash, who wrote it and the key that signs it are stored with it,
// and read back as written (ADR-0026, ADR-0027).
func TestPostgresStore_HashVersionEmitterAndKeyRoundTrip(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	last, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var prevHash []byte
	if last != nil {
		prevHash = last.Hash
	}
	for _, c := range []struct {
		v            int
		emitter, key string
	}{
		{domain.HashV1, "", ""}, {domain.HashV2, "", ""}, {domain.HashV3, "command-recorder", "b6e88eca7f335c67"},
	} {
		e := &domain.Event{ID: uniqueID("evt-version"), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ActorID: "u", PrevHash: prevHash,
			Action: "session.read", ResourceType: "session", ResourceID: "s", Success: true, Hash: []byte{1}, HashVersion: c.v, Emitter: c.emitter, KeyID: c.key}
		if err := store.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
		prevHash = e.Hash
		for _, read := range []func() (*domain.Event, error){
			func() (*domain.Event, error) { return store.Last(ctx) },
			func() (*domain.Event, error) {
				all, err := store.All(ctx)
				if err != nil {
					return nil, err
				}
				return all[len(all)-1], nil
			},
		} {
			got, err := read()
			if err != nil || got.ID != e.ID || got.HashVersion != c.v || got.Emitter != c.emitter || got.KeyID != c.key {
				t.Fatalf("%+v: read back %+v, %v", c, got, err)
			}
		}
	}
}

// DeleteThrough removes the start of the chain through an event, in one transaction, and only
// the number of events the caller expects (ADR-0032) — otherwise nothing.
func TestPostgresStore_DeleteThrough_TheStartExactlyOrNothing(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	// The whole table is the chain: start from an empty one, as the integration tests do.
	if _, err := db.ExecContext(ctx, `TRUNCATE session_alert_detection_outbox, session_alerts, audit_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewPostgresStore(db)
	run := uniqueID("delete")
	ids := make([]string, 4)
	var prevHash []byte
	for i := range ids {
		ids[i] = fmt.Sprintf("%s-evt-%d", run, i)
		event := &domain.Event{ID: ids[i], Timestamp: time.Now().UTC().Truncate(time.Microsecond), Action: "test.delete",
			ResourceType: "chain-test", ResourceID: run, Success: true, PrevHash: prevHash, Hash: []byte{byte(i)}, HashVersion: domain.HashV3}
		if err := store.Append(ctx, event); err != nil {
			t.Fatal(err)
		}
		prevHash = event.Hash
	}
	count := func() int {
		all, err := store.All(ctx)
		if err != nil {
			t.Fatal(err)
		}
		return len(all)
	}
	for name, try := range map[string]func() error{
		"fewer expected than there are": func() error { return store.DeleteThrough(ctx, ids[2], 2) },
		"more expected than there are":  func() error { return store.DeleteThrough(ctx, ids[2], 4) },
		"an event that is not there":    func() error { return store.DeleteThrough(ctx, "evt_nowhere", 1) },
	} {
		if err := try(); err == nil {
			t.Fatalf("%s: no error", name)
		}
		if n := count(); n != 4 {
			t.Fatalf("%s: %d events left, want 4 — nothing deleted", name, n)
		}
	}
	if err := store.DeleteThrough(ctx, ids[2], 3); err != nil {
		t.Fatal(err)
	}
	all, _ := store.All(ctx)
	if len(all) != 1 || all[0].ID != ids[3] {
		t.Fatalf("left %v, want only the last event", all)
	}
	_, _ = db.ExecContext(ctx, `TRUNCATE session_alert_detection_outbox, session_alerts, audit_events RESTART IDENTITY CASCADE`)
}

func TestPostgresDetectionOutbox_IsAtomicAndWorkerIsIdempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `TRUNCATE session_alerts, session_alert_detection_outbox, audit_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewPostgresStore(db)
	keys := application.RandomChainKeys()
	svc := application.NewAuditService(store).WithChainKeys(keys)
	source, err := svc.EmitEventAsWithDetails(ctx, mtls.SSHProxy, "operator-1", "session.secret_injection_failed", "session", uniqueID("alert-session"), map[string]string{"protocol": "ssh"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var pending int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox WHERE source_event_id = $1`, source.ID).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending=%d err=%v, want 1", pending, err)
	}
	// A fresh store/service instance simulates a process restart; the durable outbox survives.
	restarted := application.NewAuditService(infrastructure.NewPostgresStore(db)).WithChainKeys(keys)
	processed, err := restarted.ProcessSessionAlertDetections(ctx, 10)
	if err != nil || processed != 1 {
		t.Fatalf("processed=%d err=%v", processed, err)
	}
	var alerts, outbox, detections int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_alerts WHERE source_event_id = $1`, source.ID).Scan(&alerts); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox WHERE source_event_id = $1`, source.ID).Scan(&outbox); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM audit_events WHERE action = 'session.alert.detected' AND resource_id = $1`, source.ResourceID).Scan(&detections); err != nil {
		t.Fatal(err)
	}
	if alerts != 1 || outbox != 0 || detections != 1 {
		t.Fatalf("alerts=%d outbox=%d detection_events=%d", alerts, outbox, detections)
	}
	processed, err = restarted.ProcessSessionAlertDetections(ctx, 10)
	if err != nil || processed != 0 {
		t.Fatalf("replay processed=%d err=%v", processed, err)
	}
	if err := restarted.VerifyChain(ctx); err != nil {
		t.Fatalf("chain after detection: %v", err)
	}
}

func TestPostgresDetectionOutbox_FullQueueDoesNotAppendSourceEvent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	if _, err := db.ExecContext(ctx, `TRUNCATE session_alerts, session_alert_detection_outbox, audit_events RESTART IDENTITY CASCADE`); err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewPostgresStore(db)
	first := &domain.Event{ID: uniqueID("source-one"), Timestamp: time.Now().UTC().Truncate(time.Microsecond), Action: "session.breakglass_requested", ResourceType: "session", ResourceID: uniqueID("session"), Emitter: "session-broker", Success: true, Hash: []byte("first"), HashVersion: domain.HashV3}
	if err := store.AppendWithDetection(ctx, first, application.SessionAlertCatalogVersion, 1); err != nil {
		t.Fatal(err)
	}
	last, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	second := &domain.Event{ID: uniqueID("source-two"), Timestamp: time.Now().UTC().Truncate(time.Microsecond), Action: "session.breakglass_requested", ResourceType: "session", ResourceID: uniqueID("session"), Emitter: "session-broker", Success: true, PrevHash: last.Hash, Hash: []byte("second"), HashVersion: domain.HashV3}
	if err := store.AppendWithDetection(ctx, second, application.SessionAlertCatalogVersion, 1); err == nil {
		t.Fatal("full detection outbox accepted source event")
	}
	got, err := store.Last(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != first.ID {
		t.Fatalf("last event=%q, want first source %q", got.ID, first.ID)
	}
	var queued int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox`).Scan(&queued); err != nil || queued != 1 {
		t.Fatalf("queued=%d err=%v", queued, err)
	}
}

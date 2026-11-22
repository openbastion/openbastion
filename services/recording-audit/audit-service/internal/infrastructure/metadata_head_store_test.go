package infrastructure_test

// ADR-0116 §3-§4 on a real PostgreSQL, in a schema of its own: the event and the head are written
// together; the head is checked against the signed event even once that event has left the
// database (archived, ADR-0032); a head changed in SQL is refused.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func isolatedAuditDB(t *testing.T) *sql.DB {
	t.Helper()
	base := os.Getenv("TEST_DATABASE_URL")
	if base == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	admin, err := sql.Open("postgres", base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = admin.Close() })
	schema := fmt.Sprintf("t_heads_%d", time.Now().UnixNano())
	if _, err := admin.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = admin.Exec(`DROP SCHEMA ` + schema + ` CASCADE`) })
	sep := "?"
	if strings.Contains(base, "?") {
		sep = "&"
	}
	db, err := infrastructure.OpenPostgres(context.Background(), base+sep+"search_path="+schema)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func TestPostgresMetadataHeads_TheEventAndTheHeadTogether(t *testing.T) {
	db := isolatedAuditDB(t)
	ctx := context.Background()
	svc := application.NewAuditService(infrastructure.NewPostgresStore(db))
	digest := func(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }
	for rev := uint64(1); rev <= 3; rev++ {
		if _, err := svc.AttestSessionMetadata(ctx, "session-broker", "session_pg", rev, digest(fmt.Sprint(rev)), "k1"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.AttestSessionMetadata(ctx, "session-broker", "session_pg", 2, digest("2"), "k1"); !errors.Is(err, domain.ErrMetadataRollback) {
		t.Fatalf("a rollback: %v", err)
	}
	var events int
	_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'session.metadata_attested' AND resource_id = 'session_pg'`).Scan(&events)
	if events != 3 {
		t.Fatalf("%d attestation events, want 3 (a refusal writes none)", events)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
	head, err := svc.SessionMetadataHead(ctx, "session_pg")
	if err != nil || head.Revision != 3 {
		t.Fatalf("the head: %+v %v", head, err)
	}

	// The events archived out of the database: the head still recomputes to what the chain signed.
	if _, err := db.Exec(`DELETE FROM audit_events`); err != nil {
		t.Fatal(err)
	}
	if head, err := svc.SessionMetadataHead(ctx, "session_pg"); err != nil || head.Revision != 3 {
		t.Fatalf("the head once its events are archived: %+v %v", head, err)
	}

	// A head changed in SQL does not recompute.
	for name, q := range map[string]string{
		"revision": `UPDATE session_metadata_heads SET revision = 9`,
		"digest":   `UPDATE session_metadata_heads SET metadata_sha256 = sha256('forged')`,
	} {
		if _, err := db.Exec(`UPDATE session_metadata_heads SET revision = 3, metadata_sha256 = $1`, digest("3")); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
		if _, err := svc.SessionMetadataHead(ctx, "session_pg"); !errors.Is(err, domain.ErrMetadataHeadTampered) {
			t.Errorf("%s changed in SQL: %v", name, err)
		}
	}
}

// The store moves a head only from the one the service read: a head that moved meanwhile writes
// neither the event nor the head.
func TestPostgresMetadataHeads_AHeadThatMovedWritesNothing(t *testing.T) {
	db := isolatedAuditDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	svc := application.NewAuditService(store)
	d := sha256.Sum256([]byte("1"))
	if _, err := svc.AttestSessionMetadata(ctx, "session-broker", "s", 1, d[:], "k1"); err != nil {
		t.Fatal(err)
	}
	stale := &domain.MetadataHead{SessionID: "s", Revision: 7}
	e := &domain.Event{ID: "evt_stale", Timestamp: time.Now().UTC().Truncate(time.Microsecond), Action: domain.ActionMetadataAttested,
		ResourceType: "session", ResourceID: "s", Hash: []byte{1}, HashVersion: domain.HashV4}
	err := store.AppendAttestation(ctx, e, domain.MetadataHead{SessionID: "s", Revision: 8, Digest: d[:], KeyID: "k1", EventID: e.ID,
		EventTime: e.Timestamp, EventHash: e.Hash, ChainKeyID: "x", HashVersion: domain.HashV4}, stale)
	if err == nil {
		t.Fatal("a head that moved was overwritten")
	}
	var n int
	_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'evt_stale'`).Scan(&n)
	if n != 0 {
		t.Fatal("the event was written without its head")
	}
}

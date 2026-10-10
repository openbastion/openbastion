// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
// Mirrors services/vault/password-vault/internal/infrastructure/postgres_store_test.go
// and services/access/authorization/internal/infrastructure/postgres_store_test.go.
package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
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

func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestPostgresStore_SaveThenGet_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond) // Postgres TIMESTAMPTZ precision
	sess := &domain.Session{
		ID: uniqueID("sess"), Status: domain.StatusActive, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "incident INC-1234",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusActive || got.Protocol != "ssh" || got.RequestedBy != "jdupont" || got.Justification != "incident INC-1234" {
		t.Fatalf("unexpected round-tripped session: %+v", got)
	}
	if got.TerminatedAt != nil {
		t.Fatalf("expected a freshly created session to have no TerminatedAt, got %v", got.TerminatedAt)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, now)
	}
}

func TestPostgresStore_Save_IsAnUpsertNotAnInsertOnly(t *testing.T) {
	// Unlike every other store's Create in this project, SessionRepository
	// genuinely reuses Save to update an existing row in place —
	// TerminateSession reads a session back, flips Status/TerminatedAt,
	// and calls Save again with the same ID. A plain INSERT would fail
	// outright on the primary key the second time.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := &domain.Session{
		ID: uniqueID("sess-upsert"), Status: domain.StatusActive, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "upsert check",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save (create): %v", err)
	}

	terminatedAt := now.Add(5 * time.Minute)
	sess.Status = domain.StatusTerminated
	sess.TerminatedAt = &terminatedAt
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save (update): %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusTerminated {
		t.Fatalf("expected status %q after the second Save, got %q", domain.StatusTerminated, got.Status)
	}
	if got.TerminatedAt == nil || !got.TerminatedAt.Equal(terminatedAt) {
		t.Fatalf("expected TerminatedAt %v, got %v", terminatedAt, got.TerminatedAt)
	}
	// RequestedBy/Justification must survive the update untouched — the
	// UPSERT's DO UPDATE SET only touches status and terminated_at.
	if got.RequestedBy != "jdupont" || got.Justification != "upsert check" {
		t.Fatalf("expected unrelated fields to survive the update, got %+v", got)
	}
}

func TestPostgresStore_Get_UnknownSessionReturnsTheSameSentinelAsInMemoryStore(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)

	_, err := store.Get(context.Background(), uniqueID("does-not-exist"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected domain.ErrNotFound for an unknown session, got %v", err)
	}
}

func TestPostgresStore_Save_DeniedSessionWithNoAccountGrantRoundTrips(t *testing.T) {
	// CreateSession records a denied attempt too (Full Auditability, doc
	// 00 §2) — Status starts as StatusDenied and the session is never
	// made active. Pins that this path, not just the happy path, writes
	// cleanly.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := &domain.Session{
		ID: uniqueID("sess-denied"), Status: domain.StatusDenied, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "no access",
		CreatedAt: now, ExpiresAt: now,
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusDenied {
		t.Fatalf("expected status %q, got %q", domain.StatusDenied, got.Status)
	}
}

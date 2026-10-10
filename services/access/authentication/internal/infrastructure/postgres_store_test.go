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

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
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

// uniqueUsername avoids colliding with rows left behind by earlier runs
// against the same persistent database — users.username has a UNIQUE
// constraint, exactly like policies and privileged_accounts elsewhere in
// this project.
func uniqueUsername(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestPostgresStore_CreateThenGetByUsername_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	username := uniqueUsername("pg-user")
	u := &domain.User{ID: "user_" + username, Username: username, DisplayName: "PG Round Trip", PasswordHash: "argon2id$fake-hash", Roles: []string{"dba", "auditor"}}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.GetByUsername(ctx, username)
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if got.ID != u.ID || got.DisplayName != u.DisplayName || got.PasswordHash != u.PasswordHash {
		t.Fatalf("unexpected round-tripped user: %+v", got)
	}
	if len(got.Roles) != 2 || got.Roles[0] != "dba" || got.Roles[1] != "auditor" {
		t.Fatalf("expected roles [dba auditor] to round-trip in order, got %v", got.Roles)
	}
}

func TestPostgresStore_GetByID_FindsTheSameRowAsGetByUsername(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	username := uniqueUsername("pg-user-by-id")
	u := &domain.User{ID: "user_" + username, Username: username, DisplayName: "By ID", PasswordHash: "argon2id$fake-hash", Roles: []string{"dba"}}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.GetByID(ctx, u.ID)
	if err != nil {
		t.Fatalf("GetByID: %v", err)
	}
	if got.Username != username {
		t.Fatalf("GetByID returned username %q, want %q", got.Username, username)
	}
}

func TestPostgresStore_Create_RejectsDuplicateUsernameWithTheSameSentinelAsInMemoryStore(t *testing.T) {
	// Both storage engines must behave identically to callers — the same
	// discipline that let the two real bugs in NOTES_SANDBOX.md surface
	// as test failures instead of silently diverging between engines.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	username := uniqueUsername("pg-user-dup")
	first := &domain.User{ID: "user_a_" + username, Username: username, DisplayName: "First", PasswordHash: "h1"}
	if err := store.Create(ctx, first); err != nil {
		t.Fatalf("Create (first): %v", err)
	}

	second := &domain.User{ID: "user_b_" + username, Username: username, DisplayName: "Second", PasswordHash: "h2"}
	err := store.Create(ctx, second)
	if !errors.Is(err, infrastructure.ErrUsernameTaken) {
		t.Fatalf("expected ErrUsernameTaken for a duplicate username, got %v", err)
	}
}

func TestPostgresStore_Create_NilRolesRoundTripAsEmptyNotError(t *testing.T) {
	// Regression test for a real bug found by this test file the first
	// time it actually ran against PostgreSQL: pq.Array(nil) serializes
	// a nil []string as SQL NULL, which the roles column's NOT NULL
	// constraint (001_init.sql) rejected outright. InMemoryStore has no
	// such constraint, so a user created with a nil Roles slice (a
	// legitimate case — an account pending its first role grant)
	// compiled and passed every in-memory test, then failed the moment
	// it ran against a real database. See the fix in Create's doc
	// comment and NOTES_SANDBOX.md.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	username := uniqueUsername("pg-user-nil-roles")
	u := &domain.User{ID: "user_" + username, Username: username, DisplayName: "No Roles Yet", PasswordHash: "h"}
	if u.Roles != nil {
		t.Fatal("test setup: expected a zero-value User to have nil Roles")
	}
	if err := store.Create(ctx, u); err != nil {
		t.Fatalf("Create with nil Roles: %v", err)
	}

	got, err := store.GetByUsername(ctx, username)
	if err != nil {
		t.Fatalf("GetByUsername: %v", err)
	}
	if len(got.Roles) != 0 {
		t.Fatalf("expected nil Roles to round-trip as empty, got %v", got.Roles)
	}
}

func TestPostgresStore_GetByUsername_UnknownUserReturnsTheSameSentinelAsInMemoryStore(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)

	_, err := store.GetByUsername(context.Background(), uniqueUsername("does-not-exist"))
	if !errors.Is(err, infrastructure.ErrUserNotFound) {
		t.Fatalf("expected ErrUserNotFound for an unknown username, got %v", err)
	}
}

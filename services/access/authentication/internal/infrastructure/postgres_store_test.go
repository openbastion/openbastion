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
	"sync"
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

// ADR-0035: a federated account is found by its provider's subject, its identity replaced at
// each login, and a login attempt is taken once — of twenty callbacks racing with the same
// state, one gets it.
func TestPostgresStore_FederatedAccountsAndLoginAttempts(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	sub := uniqueID("sub")
	u := &domain.User{ID: uniqueID("user"), Username: "oidc:" + sub, DisplayName: "A", Roles: []string{"dba"},
		IdentitySource: domain.SourceOIDC, ExternalSubject: sub}
	if err := store.Create(ctx, u); err != nil {
		t.Fatal(err)
	}
	twin := &domain.User{ID: uniqueID("user"), Username: "oidc:twin-" + sub, DisplayName: "B", IdentitySource: domain.SourceOIDC, ExternalSubject: sub}
	if err := store.Create(ctx, twin); err == nil {
		t.Fatal("two accounts for the same subject")
	}
	got, err := store.GetByExternalSubject(ctx, domain.SourceOIDC, "", sub)
	if err != nil || got.ID != u.ID || got.IdentitySource != domain.SourceOIDC {
		t.Fatalf("by subject: %+v %v", got, err)
	}
	if _, err := store.GetByExternalSubject(ctx, domain.SourceLocal, "", sub); err == nil {
		t.Fatal("found under another source")
	}
	if err := store.UpdateIdentity(ctx, u.ID, "Alice", []string{"platform-admin"}); err != nil {
		t.Fatal(err)
	}
	got, _ = store.GetByID(ctx, u.ID)
	if got.DisplayName != "Alice" || len(got.Roles) != 1 || got.Roles[0] != "platform-admin" {
		t.Fatalf("after the update: %+v", got)
	}
	local := &domain.User{ID: uniqueID("user"), Username: uniqueID("local"), DisplayName: "L", PasswordHash: "x"}
	if err := store.Create(ctx, local); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.GetByID(ctx, local.ID); got.IdentitySource != domain.SourceLocal || got.ExternalSubject != "" {
		t.Fatalf("a local account: %+v", got)
	}

	state := uniqueID("state")
	exp := time.Now().UTC().Add(10 * time.Minute).Truncate(time.Microsecond)
	if err := store.SaveAttempt(ctx, domain.LoginAttempt{State: state, Verifier: "v", Nonce: "n", ExpiresAt: exp}); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	won := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			a, err := store.TakeAttempt(ctx, state)
			if err == nil {
				mu.Lock()
				won++
				mu.Unlock()
				if a.Verifier != "v" || a.Nonce != "n" || !a.ExpiresAt.Equal(exp) {
					t.Errorf("attempt read back %+v", a)
				}
			} else if !errors.Is(err, domain.ErrAttemptNotFound) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if won != 1 {
		t.Fatalf("%d callbacks took the same attempt, want 1", won)
	}
}

// ADR-0076: a subject is unique at its provider only. The same sub at two providers is two
// accounts; at one provider, never two; an attempt keeps its provider; the accounts made before are
// counted under the provider "".
func TestPostgresStore_AnAccountIsBoundToItsProvider(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	sub := uniqueID("sub")
	mk := func(provider, name string) error {
		return store.Create(ctx, &domain.User{ID: uniqueID("user"), Username: name, DisplayName: "X", Roles: []string{"dba"},
			IdentitySource: domain.SourceOIDC, IdentityProvider: provider, ExternalSubject: sub})
	}
	if err := mk("", "oidc:"+sub); err != nil {
		t.Fatal(err)
	}
	if err := mk("corp", "oidc:corp:"+sub); err != nil {
		t.Fatalf("the same sub at another provider: %v", err)
	}
	if err := mk("corp", "oidc:corp:twin-"+sub); err == nil {
		t.Fatal("two accounts for one sub at one provider")
	}
	legacy, err := store.GetByExternalSubject(ctx, domain.SourceOIDC, "", sub)
	if err != nil || legacy.Username != "oidc:"+sub || legacy.IdentityProvider != "" {
		t.Fatalf("the legacy account: %+v %v", legacy, err)
	}
	corp, err := store.GetByExternalSubject(ctx, domain.SourceOIDC, "corp", sub)
	if err != nil || corp.IdentityProvider != "corp" || corp.ID == legacy.ID {
		t.Fatalf("corp's account: %+v %v", corp, err)
	}
	if _, err := store.GetByExternalSubject(ctx, domain.SourceOIDC, "partner", sub); err == nil {
		t.Fatal("found at a provider that never vouched for it")
	}
	n, err := store.CountExternalAccounts(ctx, domain.SourceOIDC, "corp")
	if err != nil || n < 1 {
		t.Fatalf("count: %d %v", n, err)
	}
	state := uniqueID("state")
	if err := store.SaveAttempt(ctx, domain.LoginAttempt{State: state, Verifier: "v", Nonce: "n", Provider: "corp", ExpiresAt: time.Now().Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	if a, err := store.TakeAttempt(ctx, state); err != nil || a.Provider != "corp" {
		t.Fatalf("the attempt read back %+v %v", a, err)
	}
	var old int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM pg_indexes WHERE indexname = 'users_external_subject_idx'`).Scan(&old); err != nil || old != 0 {
		t.Fatalf("the index of (source, subject) is still there: %d %v", old, err)
	}
}

func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
// Mirrors services/vault/password-vault/internal/infrastructure/postgres_store_test.go.
package infrastructure_test

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
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
// the same persistent database — the policies table's UNIQUE (role,
// resource_pattern, effect) constraint would otherwise reject a second
// run's literal fixture values, exactly like vault's (target_host, name)
// constraint.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestPostgresStore_CreateThenForRoles_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	role := uniqueID("role")
	pattern := "vault:account:" + uniqueID("prod") + "-*"
	p := &domain.Policy{ID: uniqueID("policy"), Name: "pg-roundtrip", Role: role, ResourcePattern: pattern, Effect: domain.EffectAllow, CreatedBy: "it-admin"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatalf("Create: %v", err)
	}

	got, err := store.ForRoles(ctx, []string{role})
	if err != nil {
		t.Fatalf("ForRoles: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected exactly one policy for role %q, got %d", role, len(got))
	}
	if got[0].ResourcePattern != pattern || got[0].Effect != domain.EffectAllow || got[0].CreatedBy != "it-admin" {
		t.Fatalf("unexpected round-tripped policy: %+v", got[0])
	}
	if got[0].CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated by the database default")
	}
}

func TestPostgresStore_ForRoles_CoversMultipleRolesInOneQuery(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	roleA, roleB, roleC := uniqueID("role-a"), uniqueID("role-b"), uniqueID("role-c")
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "p-a", Role: roleA, ResourcePattern: "vault:account:*", Effect: domain.EffectAllow}); err != nil {
		t.Fatalf("Create (roleA): %v", err)
	}
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "p-b", Role: roleB, ResourcePattern: "vault:account:*", Effect: domain.EffectAllow}); err != nil {
		t.Fatalf("Create (roleB): %v", err)
	}

	got, err := store.ForRoles(ctx, []string{roleA, roleB, roleC})
	if err != nil {
		t.Fatalf("ForRoles: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected policies for roleA and roleB only (roleC has none), got %d: %+v", len(got), got)
	}
}

func TestPostgresStore_ForRoles_EmptyRoleListReturnsNoPolicies(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	got, err := store.ForRoles(context.Background(), nil)
	if err != nil {
		t.Fatalf("ForRoles: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no policies for an empty role list, got %d", len(got))
	}
}

func TestPostgresStore_Count_ReflectsRowsAcrossConnections(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	before, err := store.Count(ctx)
	if err != nil {
		t.Fatalf("Count (before): %v", err)
	}

	role := uniqueID("role")
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "count-check", Role: role, ResourcePattern: "authz:policy-admin", Effect: domain.EffectAllow}); err != nil {
		t.Fatalf("Create: %v", err)
	}

	// A second store value, same database — proves Count reflects what
	// another process/connection wrote, which is exactly the property
	// BootstrapAdminPolicy depends on (NOTES_SANDBOX.md).
	store2 := infrastructure.NewPostgresStore(db)
	after, err := store2.Count(ctx)
	if err != nil {
		t.Fatalf("Count (after): %v", err)
	}
	if after != before+1 {
		t.Fatalf("expected Count to increase by exactly 1, got before=%d after=%d", before, after)
	}
}

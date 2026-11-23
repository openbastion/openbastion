// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
// Mirrors services/vault/password-vault/internal/infrastructure/postgres_store_test.go.
package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/authorization/migrations"
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
// resource_pattern, action_pattern, effect) constraint would otherwise reject a second
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
	p := &domain.Policy{ID: uniqueID("policy"), Name: "pg-roundtrip", Role: role, ResourcePattern: pattern, ActionPattern: "session:create", Effect: domain.EffectAllow, CreatedBy: "it-admin"}
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
	if got[0].ResourcePattern != pattern || got[0].ActionPattern != "session:create" || got[0].Effect != domain.EffectAllow || got[0].CreatedBy != "it-admin" {
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
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "p-a", Role: roleA, ResourcePattern: "vault:account:*", ActionPattern: "*", Effect: domain.EffectAllow}); err != nil {
		t.Fatalf("Create (roleA): %v", err)
	}
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "p-b", Role: roleB, ResourcePattern: "vault:account:*", ActionPattern: "*", Effect: domain.EffectAllow}); err != nil {
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
	if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: "count-check", Role: role, ResourcePattern: "authz:policy-admin", ActionPattern: "authz:policy:create", Effect: domain.EffectAllow}); err != nil {
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

// ADR-0043: the same role, pattern and effect twice is ErrAlreadyExists, not the database's
// message (which names its constraint).
func TestPostgresStore_Create_ADuplicateIsErrAlreadyExists(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	role := uniqueID("dup-role")
	p := &domain.Policy{ID: uniqueID("p"), Name: "n", Role: role, ResourcePattern: "vault:account:x", ActionPattern: "*", Effect: domain.EffectAllow, CreatedBy: "u"}
	if err := store.Create(ctx, p); err != nil {
		t.Fatal(err)
	}
	q := *p
	q.ID = uniqueID("p")
	if err := store.Create(ctx, &q); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("a duplicate: %v", err)
	}
}

func TestPostgresStore_Create_AllowsDistinctActionPatternsForSameRoleAndResource(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	role := uniqueID("action-role")
	resource := "audit:secret-injections:all"
	for _, action := range []string{"audit:secret-injections:read", "audit:secret-injections:export"} {
		if err := store.Create(ctx, &domain.Policy{ID: uniqueID("policy"), Name: action, Role: role, ResourcePattern: resource, ActionPattern: action, Effect: domain.EffectAllow}); err != nil {
			t.Fatalf("Create(%s): %v", action, err)
		}
	}
	got, err := store.ForRoles(ctx, []string{role})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d policies, want 2", len(got))
	}
}

func TestMigration003_RequiresExplicitActionPattern(t *testing.T) {
	db := testDB(t)
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx := context.Background()
	_, err = conn.ExecContext(ctx, `CREATE TEMP TABLE policies (id TEXT PRIMARY KEY, name TEXT NOT NULL, role TEXT NOT NULL, resource_pattern TEXT NOT NULL, effect TEXT NOT NULL, created_by TEXT, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), CONSTRAINT policies_role_resource_pattern_effect_key UNIQUE (role, resource_pattern, effect))`)
	if err != nil {
		t.Fatal(err)
	}
	sql, err := migrations.Files.ReadFile("002_action_pattern.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, string(sql)); err != nil {
		t.Fatalf("apply action-pattern migration: %v", err)
	}
	sql, err = migrations.Files.ReadFile("003_require_explicit_action_pattern.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(ctx, string(sql)); err != nil {
		t.Fatalf("apply explicit-action migration: %v", err)
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO policies (id, name, role, resource_pattern, effect) VALUES ('missing-action', 'missing', 'role', 'resource:*', 'allow')`); err == nil {
		t.Fatal("policy insert without action_pattern unexpectedly succeeded")
	}
	if _, err := conn.ExecContext(ctx, `INSERT INTO policies (id, name, role, resource_pattern, action_pattern, effect) VALUES ('explicit-wildcard', 'explicit wildcard', 'role', 'resource:*', '*', 'allow')`); err != nil {
		t.Fatalf("explicit wildcard policy should remain possible: %v", err)
	}
}

// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
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

func TestPostgresStore_AccountCreateThenGet_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	id := uniqueID("acc")
	account := &domain.PrivilegedAccount{ID: id, Name: id, Username: "root", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}
	if err := store.Create(ctx, account); err != nil {
		t.Fatalf("Create: %v", err)
	}
	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Name != id || got.Username != "root" || got.TargetHost != id+":22" {
		t.Fatalf("unexpected round-tripped account: %+v", got)
	}
	if got.CreatedAt.IsZero() {
		t.Fatal("expected CreatedAt to be populated by the database default")
	}
}

func TestPostgresStore_Get_ReturnsErrNotFoundForUnknownID(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	if _, err := store.Get(context.Background(), "does-not-exist-in-postgres"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected domain.ErrNotFound, got %v", err)
	}
}

func TestPostgresStore_SecretVersioning_CurrentVersionReflectsSupersession(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	accountID := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: accountID, Name: accountID, Username: "u", TargetHost: accountID + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create account: %v", err)
	}
	v1 := &domain.SecretVersion{ID: uniqueID("secret"), PrivilegedAccountID: accountID, EncryptedMaterial: []byte("cipher-v1"), EncryptionKeyID: "key1", Version: 1}
	if err := store.AddVersion(ctx, v1); err != nil {
		t.Fatalf("AddVersion v1: %v", err)
	}
	current, err := store.CurrentVersion(ctx, accountID)
	if err != nil {
		t.Fatalf("CurrentVersion (before rotation): %v", err)
	}
	if current.Version != 1 {
		t.Fatalf("expected version 1 to be current, got %d", current.Version)
	}
	if err := store.SupersedeCurrent(ctx, accountID); err != nil {
		t.Fatalf("SupersedeCurrent: %v", err)
	}
	v2 := &domain.SecretVersion{ID: uniqueID("secret"), PrivilegedAccountID: accountID, EncryptedMaterial: []byte("cipher-v2"), EncryptionKeyID: "key1", Version: 2}
	if err := store.AddVersion(ctx, v2); err != nil {
		t.Fatalf("AddVersion v2: %v", err)
	}
	current, err = store.CurrentVersion(ctx, accountID)
	if err != nil {
		t.Fatalf("CurrentVersion (after rotation): %v", err)
	}
	if current.Version != 2 || string(current.EncryptedMaterial) != "cipher-v2" {
		t.Fatalf("expected version 2 to be current after supersession, got %+v", current)
	}
}

func TestPostgresStore_ScopeGrant_ConsumeIfValidIsSingleUse(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	accountID := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: accountID, Name: accountID, Username: "u", TargetHost: accountID + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create account: %v", err)
	}
	token := uniqueID("scope")
	grant := &domain.ScopeGrant{Token: token, SessionID: "s1", PrivilegedAccountID: accountID, ProxyServiceID: "ssh-proxy-1", ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := store.Save(ctx, grant); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.ConsumeIfValid(ctx, token, "ssh-proxy-1"); err != nil {
		t.Fatalf("first ConsumeIfValid should succeed: %v", err)
	}
	if _, err := store.ConsumeIfValid(ctx, token, "ssh-proxy-1"); err == nil {
		t.Fatal("expected a reused token to be rejected")
	}
}

func TestPostgresStore_ScopeGrant_ConsumeIfValidRejectsWrongProxy(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	accountID := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: accountID, Name: accountID, Username: "u", TargetHost: accountID + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create account: %v", err)
	}
	token := uniqueID("scope")
	grant := &domain.ScopeGrant{Token: token, SessionID: "s1", PrivilegedAccountID: accountID, ProxyServiceID: "ssh-proxy-1", ExpiresAt: time.Now().UTC().Add(time.Minute)}
	if err := store.Save(ctx, grant); err != nil {
		t.Fatalf("Save: %v", err)
	}
	if _, err := store.ConsumeIfValid(ctx, token, "database-proxy-1"); err == nil {
		t.Fatal("expected ConsumeIfValid to reject a proxy identity different from the one authorized")
	}
}

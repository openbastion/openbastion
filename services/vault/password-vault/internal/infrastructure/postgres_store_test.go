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

func TestPostgresStore_List_ExcludesDisabledAndPaginates(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	// A unique id prefix per run (uniqueID) keeps this test independent of
	// whatever other rows a shared test database already has — List's
	// totalItems and page contents are asserted relative to the three rows
	// created here, not in absolute terms.
	base := uniqueID("list")
	ids := []string{base + "_a", base + "_b", base + "_c"}
	for _, id := range ids {
		if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	if err := store.Disable(ctx, ids[1]); err != nil {
		t.Fatalf("Disable %s: %v", ids[1], err)
	}

	page1, totalBeforeOthers, err := store.List(ctx, 1, 1000)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var seenIDs []string
	for _, a := range page1 {
		for _, id := range ids {
			if a.ID == id {
				seenIDs = append(seenIDs, a.ID)
			}
		}
	}
	if len(seenIDs) != 2 {
		t.Fatalf("expected 2 of the 3 seeded accounts (the disabled one excluded) to appear, got %v", seenIDs)
	}
	for _, id := range seenIDs {
		if id == ids[1] {
			t.Fatalf("expected disabled account %s to be excluded from List", ids[1])
		}
	}
	if totalBeforeOthers < 2 {
		t.Fatalf("expected totalItems to be at least the 2 enabled seeded accounts, got %d", totalBeforeOthers)
	}

	// Pagination: page size 1 against exactly these two enabled accounts,
	// isolated with a dedicated id prefix so unrelated rows can't land on
	// either page and break the count.
	pageBase := uniqueID("page")
	pageIDs := []string{pageBase + "_a", pageBase + "_b"}
	for _, id := range pageIDs {
		if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
			t.Fatalf("Create %s: %v", id, err)
		}
	}
	firstPage, _, err := store.List(ctx, 1, 1)
	if err != nil {
		t.Fatalf("List page 1: %v", err)
	}
	if len(firstPage) != 1 {
		t.Fatalf("expected exactly 1 account with pageSize=1, got %d", len(firstPage))
	}
}

func TestPostgresStore_Disable_IsIdempotentAndReflectedByGet(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	id := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := store.Get(ctx, id); err != nil || got.DisabledAt != nil {
		t.Fatalf("expected a freshly created account to have no DisabledAt, got %+v err=%v", got, err)
	}

	if err := store.Disable(ctx, id); err != nil {
		t.Fatalf("Disable: %v", err)
	}
	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after Disable: %v", err)
	}
	if got.DisabledAt == nil {
		t.Fatal("expected DisabledAt to be populated after Disable")
	}

	// Idempotent: disabling an already-disabled account must not error.
	if err := store.Disable(ctx, id); err != nil {
		t.Fatalf("second Disable (idempotency): %v", err)
	}
}

func TestPostgresStore_MarkRotated_SetsLastRotatedAt(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	id := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := store.Get(ctx, id); err != nil || got.LastRotatedAt != nil {
		t.Fatalf("expected a freshly created account to have no LastRotatedAt, got %+v err=%v", got, err)
	}

	if err := store.MarkRotated(ctx, id); err != nil {
		t.Fatalf("MarkRotated: %v", err)
	}
	got, err := store.Get(ctx, id)
	if err != nil {
		t.Fatalf("Get after MarkRotated: %v", err)
	}
	if got.LastRotatedAt == nil {
		t.Fatal("expected LastRotatedAt to be populated after MarkRotated")
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

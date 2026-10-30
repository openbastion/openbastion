// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
	"github.com/openbastion/openbastion/services/vault/password-vault/migrations"
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

// A pending version (ADR-0037) is never the current one, there is one at most per account, and
// promoting it supersedes the old one in one step.
func TestPostgresStore_PendingVersion_Lifecycle(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	id := fmt.Sprintf("acc_pending_%d", time.Now().UnixNano())
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: "h:22", Protocol: "ssh", RotationPolicy: domain.RotationManual, ReconciliationAccountID: "rec_x"}); err != nil {
		t.Fatal(err)
	}
	if a, _ := store.Get(ctx, id); a.ReconciliationAccountID != "rec_x" {
		t.Fatalf("reconciliation read back %q", a.ReconciliationAccountID)
	}
	if err := store.AddVersion(ctx, &domain.SecretVersion{ID: id + "-v1", PrivilegedAccountID: id, EncryptedMaterial: []byte("v1"), EncryptionKeyID: "k", Version: 1}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPending(ctx, &domain.SecretVersion{ID: id + "-v2", PrivilegedAccountID: id, EncryptedMaterial: []byte("v2"), EncryptionKeyID: "k", Version: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPending(ctx, &domain.SecretVersion{ID: id + "-v3", PrivilegedAccountID: id, EncryptedMaterial: []byte("v3"), EncryptionKeyID: "k", Version: 3}); !errors.Is(err, domain.ErrRotationInProgress) {
		t.Fatalf("a second pending version: %v", err)
	}
	if cur, _ := store.CurrentVersion(ctx, id); cur == nil || cur.Version != 1 {
		t.Fatalf("current while pending: %+v", cur)
	}
	if p, _ := store.PendingVersion(ctx, id); p == nil || p.Version != 2 || !p.Pending {
		t.Fatalf("pending: %+v", p)
	}
	if err := store.PromotePending(ctx, id, 2); err != nil {
		t.Fatal(err)
	}
	if cur, _ := store.CurrentVersion(ctx, id); cur == nil || cur.Version != 2 || string(cur.EncryptedMaterial) != "v2" {
		t.Fatalf("current after promotion: %+v", cur)
	}
	if p, _ := store.PendingVersion(ctx, id); p != nil {
		t.Fatal("still pending after promotion")
	}
	_ = store.AddPending(ctx, &domain.SecretVersion{ID: id + "-v3b", PrivilegedAccountID: id, EncryptedMaterial: []byte("v3"), EncryptionKeyID: "k", Version: 3})
	if err := store.DiscardPending(ctx, id, 3); err != nil {
		t.Fatal(err)
	}
	if cur, _ := store.CurrentVersion(ctx, id); cur.Version != 2 {
		t.Fatalf("current after a discard: %d", cur.Version)
	}
}

// The pinned host key (ADR-0039): an account created without one has none (as one migrated
// from before 003_host_key.sql does), SetHostKey stores it, Get and List read it back.
func TestPostgresStore_HostKey_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	id := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual}); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if got, err := store.Get(ctx, id); err != nil || got.HostKey != "" {
		t.Fatalf("a new account without a key: %+v err=%v", got, err)
	}
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIC4DoGHWLAW6lDc2nUPEk0OinOIhont/UMnJzJUQCiKK"
	if err := store.SetHostKey(ctx, id, key); err != nil {
		t.Fatalf("SetHostKey: %v", err)
	}
	if got, err := store.Get(ctx, id); err != nil || got.HostKey != key {
		t.Fatalf("Get after SetHostKey: %q err=%v", got.HostKey, err)
	}
	accounts, _, err := store.List(ctx, 1, 100)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, a := range accounts {
		if a.ID == id {
			found = a.HostKey == key
		}
	}
	if !found {
		t.Fatal("List does not read the pinned key back")
	}
	if err := store.SetHostKey(ctx, uniqueID("nobody"), key); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("SetHostKey of an unknown account: %v", err)
	}
	// Created with a key: stored at once.
	id2 := uniqueID("acc")
	if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id2, Name: id2, Username: "u", TargetHost: id2 + ":22", Protocol: "ssh", RotationPolicy: domain.RotationManual, HostKey: key}); err != nil {
		t.Fatal(err)
	}
	if got, _ := store.Get(ctx, id2); got.HostKey != key {
		t.Fatalf("Create with a key stored %q", got.HostKey)
	}
}

// Scheduled rotations (ADR-0040) on a real database: what is due is listed, the longest
// overdue first; a claim is taken once; a taken account waits; a rotation pushes it back; a
// scheduled account from before 004_rotation_schedule.sql gets its 30 days.
func TestPostgresStore_ScheduledRotation_DueClaimAndUpgrade(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	mk := func(policy domain.RotationPolicy, days int, ageDays int) string {
		id := uniqueID("sched")
		if err := store.Create(ctx, &domain.PrivilegedAccount{ID: id, Name: id, Username: "u", TargetHost: id + ":22", Protocol: "ssh",
			RotationPolicy: policy, RotationIntervalDays: days}); err != nil {
			t.Fatal(err)
		}
		if _, err := db.ExecContext(ctx, `UPDATE privileged_accounts SET created_at = now() - $2 * interval '1 day' WHERE id = $1`, id, ageDays); err != nil {
			t.Fatal(err)
		}
		return id
	}
	older := mk(domain.RotationScheduled, 1, 10) // overdue by 9 days
	newer := mk(domain.RotationScheduled, 1, 3)  // overdue by 2 days
	notYet := mk(domain.RotationScheduled, 30, 3)
	manual := mk(domain.RotationManual, 0, 400)
	disabled := mk(domain.RotationScheduled, 1, 10)
	if err := store.Disable(ctx, disabled); err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	ids := func(now time.Time) []string {
		due, err := store.ListDueForRotation(ctx, now, time.Hour, 1000)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, a := range due {
			if strings.HasPrefix(a.ID, "sched_") && (a.ID == older || a.ID == newer || a.ID == notYet || a.ID == manual || a.ID == disabled) {
				out = append(out, a.ID)
			}
		}
		return out
	}
	if got := ids(now); len(got) != 2 || got[0] != older || got[1] != newer {
		t.Fatalf("due: %v, want [%s %s]", got, older, newer)
	}
	if a, _ := store.Get(ctx, older); a.RotationIntervalDays != 1 || a.RotationAttemptedAt != nil {
		t.Fatalf("read back: %+v", a)
	}

	if ok, err := store.ClaimRotation(ctx, older, now, time.Hour); err != nil || !ok {
		t.Fatalf("first claim: %v %v", ok, err)
	}
	if ok, _ := store.ClaimRotation(ctx, older, now, time.Hour); ok {
		t.Fatal("a second claim within the hour was taken")
	}
	if ok, _ := store.ClaimRotation(ctx, notYet, now, time.Hour); ok {
		t.Fatal("an account that is not due was taken")
	}
	if got := ids(now); len(got) != 1 || got[0] != newer {
		t.Fatalf("after the claim: %v", got)
	}
	if ok, _ := store.ClaimRotation(ctx, older, now.Add(61*time.Minute), time.Hour); !ok {
		t.Fatal("not taken again after the hour")
	}
	if err := store.MarkRotated(ctx, newer); err != nil {
		t.Fatal(err)
	}
	if got := ids(now.Add(3 * time.Hour)); len(got) != 1 || got[0] != older {
		t.Fatalf("a rotated account is still due: %v", got)
	}

	// The upgrade: a scheduled account with no interval, as before the migration.
	legacy := mk(domain.RotationScheduled, 0, 40)
	sqlText, err := migrations.Files.ReadFile("004_rotation_schedule.sql")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, string(sqlText)); err != nil {
		t.Fatalf("004 again (idempotent): %v", err)
	}
	if a, _ := store.Get(ctx, legacy); a.RotationIntervalDays != 30 {
		t.Fatalf("the legacy scheduled account has %d days", a.RotationIntervalDays)
	}
	if a, _ := store.Get(ctx, manual); a.RotationIntervalDays != 0 {
		t.Fatalf("a manual account got %d days", a.RotationIntervalDays)
	}
}

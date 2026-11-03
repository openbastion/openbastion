package application_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

type fakeAuthz struct {
	allowed      bool
	reason       string
	err          error
	calls        int
	lastRoles    []string
	lastResource string
	lastAction   string
}

func (f *fakeAuthz) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	f.calls++
	f.lastRoles, f.lastResource, f.lastAction = actorRoles, resource, action
	if f.err != nil {
		return false, "", f.err
	}
	return f.allowed, f.reason, nil
}

func newTestService(t *testing.T) *application.VaultService {
	t.Helper()
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	return application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).
		WithRotation(newFakeTarget(), &fakeAudit{})
}

// reconcilable gives accountID a reconciliation account on its target (ADR-0037): the
// rotations of these tests reach a target, as every rotation now must.
func reconcilable(t *testing.T, svc *application.VaultService, accountID string) {
	t.Helper()
	ctx := context.Background()
	a, err := svc.GetAccount(ctx, accountID)
	if err != nil {
		t.Fatalf("reconcilable: %v", err)
	}
	recID := "rec_" + accountID
	if _, err := svc.GetAccount(ctx, recID); err != nil {
		if err := onboardTest(svc, ctx, adminRoles, recID, "reconciliation", "reconciler", a.TargetHost, "ssh", domain.RotationManual, []byte("root-secret")); err != nil {
			t.Fatalf("reconcilable: %v", err)
		}
	}
	if err := svc.SetReconciliationAccount(ctx, adminRoles, accountID, recID); err != nil {
		t.Fatalf("reconcilable: %v", err)
	}
}

var adminRoles = []string{"vault-admin"}

func TestFetchCredential_RequiresPriorAuthorization(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if _, err := svc.FetchCredential(ctx, "never-issued-token", "ssh-proxy"); err == nil {
		t.Fatal("expected FetchCredential to fail without a prior AuthorizeScope")
	}
}

func TestFetchCredential_RejectsWrongProxyIdentity(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	token, _, err := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy", time.Minute)
	if err != nil {
		t.Fatalf("AuthorizeScope: %v", err)
	}
	if _, err := svc.FetchCredential(ctx, token, "database-proxy-1"); err == nil {
		t.Fatal("expected FetchCredential to reject a proxy identity different from the one authorized")
	}
}

func TestFetchCredential_ScopeTokenIsSingleUse(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	token, _, _ := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy", time.Minute)
	if _, err := svc.FetchCredential(ctx, token, "ssh-proxy"); err != nil {
		t.Fatalf("first FetchCredential should succeed: %v", err)
	}
	if _, err := svc.FetchCredential(ctx, token, "ssh-proxy"); err == nil {
		t.Fatal("expected a replayed scope token to be rejected (single-use)")
	}
}

func TestFetchCredential_ReturnsPlaintextMatchingOnboarded(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret-value"))
	token, _, _ := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy", time.Minute)
	material, err := fetchMaterial(svc, ctx, token, "ssh-proxy")
	if err != nil {
		t.Fatalf("FetchCredential: %v", err)
	}
	if string(material) != "s3cret-value" {
		t.Fatalf("got %q, want %q", material, "s3cret-value")
	}
}

func TestRotate_SupersedesPreviousVersion(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("old-secret-value"))
	reconcilable(t, svc, "acc1")
	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("new-secret-value")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	token, _, _ := svc.AuthorizeScope(ctx, "session2", "acc1", "ssh-proxy", time.Minute)
	material, err := fetchMaterial(svc, ctx, token, "ssh-proxy")
	if err != nil {
		t.Fatalf("FetchCredential: %v", err)
	}
	if string(material) != "new-secret-value" {
		t.Fatalf("expected rotated value, got %q", material)
	}
	if bytes.Contains(material, []byte("old-secret-value")) {
		t.Fatal("rotated credential must not resemble the superseded one")
	}
}

func TestGetAccount_ReturnsMetadataOnly(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "prod-db-01-root", "root", "10.0.4.12:22", "ssh", domain.RotationManual, []byte("s3cret"))
	account, err := svc.GetAccount(ctx, "acc1")
	if err != nil {
		t.Fatalf("GetAccount: %v", err)
	}
	if account.Username != "root" || account.TargetHost != "10.0.4.12:22" || account.Name != "prod-db-01-root" {
		t.Fatalf("unexpected account metadata: %+v", account)
	}
}

func TestGetAccount_FailsForUnknownAccount(t *testing.T) {
	svc := newTestService(t)
	if _, err := svc.GetAccount(context.Background(), "does-not-exist"); err == nil {
		t.Fatal("expected GetAccount to fail for an unknown account id")
	}
}

func TestRotate_AutoGeneratesSecretWhenNoneProvided(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("old-secret-value"))
	reconcilable(t, svc, "acc1")
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate with no explicit secret: %v", err)
	}
	token, _, _ := svc.AuthorizeScope(ctx, "session2", "acc1", "ssh-proxy", time.Minute)
	material, err := fetchMaterial(svc, ctx, token, "ssh-proxy")
	if err != nil {
		t.Fatalf("FetchCredential: %v", err)
	}
	if len(material) == 0 {
		t.Fatal("expected a non-empty auto-generated secret")
	}
	if string(material) == "old-secret-value" {
		t.Fatal("expected the auto-generated secret to differ from the superseded one")
	}
}

func TestRotate_AutoGeneratesDifferentSecretsEachTime(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial"))
	reconcilable(t, svc, "acc1")
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate 1: %v", err)
	}
	token1, _, _ := svc.AuthorizeScope(ctx, "s1", "acc1", "ssh-proxy", time.Minute)
	first, _ := fetchMaterial(svc, ctx, token1, "ssh-proxy")
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate 2: %v", err)
	}
	token2, _, _ := svc.AuthorizeScope(ctx, "s2", "acc1", "ssh-proxy", time.Minute)
	second, _ := fetchMaterial(svc, ctx, token2, "ssh-proxy")
	if string(first) == string(second) {
		t.Fatal("expected two successive auto-generated rotations to produce different secrets")
	}
}

func TestRotate_IncrementsVersionNumberEachTime(t *testing.T) {
	// Pins the fix for a real bug: storeVersion used to compute the next
	// version number by calling CurrentVersion AFTER SupersedeCurrent had
	// already cleared every row's superseded_at — so it always recomputed
	// version 1, on every rotation. InMemoryStore's AddVersion just
	// appends with no uniqueness check, so this was invisible here; only
	// PostgresStore's UNIQUE (privileged_account_id, version) constraint
	// ever surfaced it (see NOTES_SANDBOX.md). This test pins the correct
	// behavior directly, independent of which storage engine enforces it.
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()

	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("v1")); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
	reconcilable(t, svc, "acc1")
	v1, err := store.CurrentVersion(ctx, "acc1")
	if err != nil {
		t.Fatalf("CurrentVersion after onboarding: %v", err)
	}
	if v1.Version != 1 {
		t.Fatalf("expected version 1 after onboarding, got %d", v1.Version)
	}

	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("v2")); err != nil {
		t.Fatalf("Rotate (1st): %v", err)
	}
	v2, err := store.CurrentVersion(ctx, "acc1")
	if err != nil {
		t.Fatalf("CurrentVersion after 1st rotation: %v", err)
	}
	if v2.Version != 2 {
		t.Fatalf("expected version 2 after the first rotation, got %d", v2.Version)
	}

	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("v3")); err != nil {
		t.Fatalf("Rotate (2nd): %v", err)
	}
	v3, err := store.CurrentVersion(ctx, "acc1")
	if err != nil {
		t.Fatalf("CurrentVersion after 2nd rotation: %v", err)
	}
	if v3.Version != 3 {
		t.Fatalf("expected version 3 after the second rotation, got %d", v3.Version)
	}
}

func TestOnboardAccount_LeavesLastRotatedAtNilBeforeAnyRotation(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial")); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
	account, err := store.Get(ctx, "acc1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if account.LastRotatedAt != nil {
		t.Fatalf("expected LastRotatedAt to stay nil until an actual rotation, got %v", account.LastRotatedAt)
	}
}

func TestRotate_SetsLastRotatedAt(t *testing.T) {
	// Pins the fix for a real bug of the same shape as the version-number
	// one above: last_rotated_at has existed in the DDL and been scanned
	// by PostgresStore.Get since the start, but Rotate never wrote to it —
	// found while wiring lastRotatedAt into the HTTP response
	// (interfaces/http.go's accountResponse). See NOTES_SANDBOX.md.
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial")); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
	reconcilable(t, svc, "acc1")

	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("rotated-once")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	afterFirst, err := store.Get(ctx, "acc1")
	if err != nil {
		t.Fatalf("Get after 1st rotation: %v", err)
	}
	if afterFirst.LastRotatedAt == nil {
		t.Fatal("expected LastRotatedAt to be set after a rotation")
	}

	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("rotated-twice")); err != nil {
		t.Fatalf("Rotate (2nd): %v", err)
	}
	afterSecond, err := store.Get(ctx, "acc1")
	if err != nil {
		t.Fatalf("Get after 2nd rotation: %v", err)
	}
	if afterSecond.LastRotatedAt == nil {
		t.Fatal("expected LastRotatedAt to still be set after a second rotation")
	}
	if afterSecond.LastRotatedAt.Before(*afterFirst.LastRotatedAt) {
		t.Fatalf("expected the second rotation's timestamp (%v) not to precede the first's (%v)", afterSecond.LastRotatedAt, afterFirst.LastRotatedAt)
	}
}

func TestOnboardAccount_EncryptedMaterialNeverContainsPlaintext(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	plaintext := []byte("a-very-identifiable-plaintext-marker")
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, plaintext); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
	version, err := store.CurrentVersion(ctx, "acc1")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if bytes.Contains(version.EncryptedMaterial, plaintext) {
		t.Fatal("encrypted_material must never contain the plaintext credential — envelope encryption failed")
	}
	if version.EncryptionKeyID == "" {
		t.Fatal("encryption_key_id must reference the KMS key, never leave it unset")
	}
}

func TestOnboardAccount_DeniedWithoutAuthorization(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	authz := &fakeAuthz{allowed: false, reason: "no policy matches"}
	svc := application.NewVaultService(store, store, store, kms, authz).WithRotation(newFakeTarget(), &fakeAudit{})
	err := onboardTest(svc, context.Background(), []string{"nobody"}, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if err == nil {
		t.Fatal("expected OnboardAccount to be denied without a matching authorization policy")
	}
	if authz.calls != 1 {
		t.Fatalf("expected exactly one CheckAccess call, got %d", authz.calls)
	}
	if authz.lastResource != "vault:account-admin:acc1" {
		t.Fatalf("expected the admin resource namespace to be checked, got %q", authz.lastResource)
	}
	if _, err := store.Get(context.Background(), "acc1"); err == nil {
		t.Fatal("expected no account to have been created after a denied OnboardAccount")
	}
}

func TestOnboardAccount_FailsClosedWhenAuthorizationUnreachable(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	authz := &fakeAuthz{err: errors.New("authorization service unreachable")}
	svc := application.NewVaultService(store, store, store, kms, authz).WithRotation(newFakeTarget(), &fakeAudit{})
	if err := onboardTest(svc, context.Background(), adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret")); err == nil {
		t.Fatal("expected OnboardAccount to fail closed when Authorization is unreachable")
	}
}

func TestRotate_DeniedWithoutAuthorization(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	permissive := &fakeAuthz{allowed: true}
	svc := application.NewVaultService(store, store, store, kms, permissive).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial")); err != nil {
		t.Fatalf("onboarding setup: %v", err)
	}
	restrictive := &fakeAuthz{allowed: false, reason: "role lost admin rights"}
	svc2 := application.NewVaultService(store, store, store, kms, restrictive).WithRotation(newFakeTarget(), &fakeAudit{})
	if err := svc2.Rotate(ctx, []string{"someone-without-rights"}, "acc1", nil); err == nil {
		t.Fatal("expected Rotate to be denied without a matching authorization policy")
	}
	if restrictive.lastAction != "vault:account:rotate" {
		t.Fatalf("expected the rotate action to be checked, got %q", restrictive.lastAction)
	}
}

func TestOnboardAccount_SessionCreationRightsAloneDoNotGrantAdminAccess(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	authz := &sessionOnlyAuthz{}
	svc := application.NewVaultService(store, store, store, kms, authz).WithRotation(newFakeTarget(), &fakeAudit{})
	err := onboardTest(svc, context.Background(), []string{"dba"}, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if err == nil {
		t.Fatal("expected onboarding to be denied for a role with only session-creation rights")
	}
}

func TestListAccounts_ExcludesDisabledAccounts(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target1", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s1"))
	_ = onboardTest(svc, ctx, adminRoles, "acc2", "target2", "root", "10.0.0.2:22", "ssh", domain.RotationManual, []byte("s2"))
	if err := svc.DisableAccount(ctx, adminRoles, "acc2"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}

	accounts, totalItems, err := svc.ListAccounts(ctx, adminRoles, 1, 20)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if totalItems != 1 {
		t.Fatalf("expected totalItems=1 after disabling one of two accounts, got %d", totalItems)
	}
	if len(accounts) != 1 || accounts[0].ID != "acc1" {
		t.Fatalf("expected only acc1 to remain listed, got %+v", accounts)
	}
}

func TestListAccounts_ClampsPageAndPageSize(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		id := string(rune('a' + i))
		// A name of its own: the database refuses one name twice on one target, and the memory
		// store now does too (ADR-0043).
		if err := onboardTest(svc, ctx, adminRoles, id, "target-"+id, "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s")); err != nil {
			t.Fatal(err)
		}
	}
	// page=0 and a pageSize far beyond the documented maximum (docs/api/rest/openapi.yaml:
	// pageSize max 100) must not panic or bypass pagination — both are
	// clamped by ListAccounts itself, not left to the caller.
	accounts, totalItems, err := svc.ListAccounts(ctx, adminRoles, 0, 10000)
	if err != nil {
		t.Fatalf("ListAccounts: %v", err)
	}
	if totalItems != 3 {
		t.Fatalf("expected totalItems=3, got %d", totalItems)
	}
	if len(accounts) != 3 {
		t.Fatalf("expected a clamped page=0 to behave as page=1 and return all 3 accounts, got %d", len(accounts))
	}
}

func TestListAccounts_DeniedWithoutAuthorization(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	authz := &fakeAuthz{allowed: false, reason: "no policy matches"}
	svc := application.NewVaultService(store, store, store, kms, authz).WithRotation(newFakeTarget(), &fakeAudit{})
	if _, _, err := svc.ListAccounts(context.Background(), []string{"nobody"}, 1, 20); err == nil {
		t.Fatal("expected ListAccounts to be denied without a matching authorization policy")
	}
	if authz.lastResource != "vault:account-admin:*" {
		t.Fatalf("expected the wildcard admin resource to be checked for a list, got %q", authz.lastResource)
	}
}

func TestDisableAccount_GetAccountThenReturns404(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if err := svc.DisableAccount(ctx, adminRoles, "acc1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}
	if _, err := svc.GetAccount(ctx, "acc1"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected GetAccount to report a disabled account as not found, got %v", err)
	}
}

func TestDisableAccount_FailsForUnknownAccount(t *testing.T) {
	svc := newTestService(t)
	if err := svc.DisableAccount(context.Background(), adminRoles, "does-not-exist"); err == nil {
		t.Fatal("expected DisableAccount to fail for an unknown account id")
	}
}

func TestDisableAccount_DeniedWithoutAuthorization(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	permissive := &fakeAuthz{allowed: true}
	svc := application.NewVaultService(store, store, store, kms, permissive).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret")); err != nil {
		t.Fatalf("onboarding setup: %v", err)
	}
	restrictive := &fakeAuthz{allowed: false, reason: "role lost admin rights"}
	svc2 := application.NewVaultService(store, store, store, kms, restrictive).WithRotation(newFakeTarget(), &fakeAudit{})
	if err := svc2.DisableAccount(ctx, []string{"someone-without-rights"}, "acc1"); err == nil {
		t.Fatal("expected DisableAccount to be denied without a matching authorization policy")
	}
	if restrictive.lastAction != "vault:account:delete" {
		t.Fatalf("expected the delete action to be checked, got %q", restrictive.lastAction)
	}
	// Confirm the denial actually left the account enabled (no delete leaked
	// through before the check, nor after a short-circuit).
	if account, err := store.Get(ctx, "acc1"); err != nil || account.DisabledAt != nil {
		t.Fatalf("expected acc1 to remain enabled after a denied DisableAccount, got account=%+v err=%v", account, err)
	}
}

func TestDisableAccount_BlocksRotate(t *testing.T) {
	// A disabled account must behave as if it did not exist for every
	// operation, not only for reads and scope issuance. Before this check,
	// Rotate silently created a new secret version and stamped
	// LastRotatedAt on a disabled account — nothing leaked (AuthorizeScope
	// still refused it), but the row kept changing after "deletion".
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), &fakeAudit{})
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial")); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
	reconcilable(t, svc, "acc1")
	if err := svc.DisableAccount(ctx, adminRoles, "acc1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}

	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected Rotate to reject a disabled account as not found, got %v", err)
	}

	version, err := store.CurrentVersion(ctx, "acc1")
	if err != nil {
		t.Fatalf("CurrentVersion: %v", err)
	}
	if version.Version != 1 {
		t.Fatalf("expected the secret to stay at version 1 after a refused rotation, got %d", version.Version)
	}
	account, err := store.Get(ctx, "acc1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if account.LastRotatedAt != nil {
		t.Fatalf("expected LastRotatedAt to stay nil after a refused rotation, got %v", account.LastRotatedAt)
	}
}

func TestDisableAccount_BlocksAuthorizeScope(t *testing.T) {
	// This is the actual security property DisableAccount exists to
	// provide: once disabled, a session that reaches this far (say, one
	// whose request landed in a race with the disable) must not be able
	// to mint a usable credential scope either. AuthorizeScope checks
	// DisabledAt itself, independent of GetAccount's own check, as
	// defense in depth — see its doc comment.
	svc := newTestService(t)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if err := svc.DisableAccount(ctx, adminRoles, "acc1"); err != nil {
		t.Fatalf("DisableAccount: %v", err)
	}
	if _, _, err := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy", time.Minute); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected AuthorizeScope to reject a disabled account as not found, got %v", err)
	}
}

type sessionOnlyAuthz struct{}

func (sessionOnlyAuthz) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	if len(resource) >= len("vault:account:") && resource[:len("vault:account:")] == "vault:account:" {
		return true, "session-creation policy matched", nil
	}
	return false, "no policy matches this resource", nil
}

func TestClampPage(t *testing.T) {
	cases := []struct{ page, size, wantPage, wantSize int }{
		{0, 0, 1, 20},    // nothing requested: page 1, default size
		{-5, -1, 1, 20},  // negatives behave like absent
		{3, 5, 3, 5},     // in range: untouched
		{2, 100, 2, 100}, // the maximum itself is allowed
		{1, 101, 1, 100}, // above the maximum: clamped
		{1, 100000, 1, 100},
	}
	for _, c := range cases {
		if p, s := application.ClampPage(c.page, c.size); p != c.wantPage || s != c.wantSize {
			t.Errorf("ClampPage(%d, %d) = (%d, %d), want (%d, %d)", c.page, c.size, p, s, c.wantPage, c.wantSize)
		}
	}
}

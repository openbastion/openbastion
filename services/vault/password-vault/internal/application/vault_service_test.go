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
	return application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true})
}

var adminRoles = []string{"vault-admin"}

func TestFetchCredential_RequiresPriorAuthorization(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if _, _, err := svc.FetchCredential(ctx, "never-issued-token", "ssh-proxy-1"); err == nil {
		t.Fatal("expected FetchCredential to fail without a prior AuthorizeScope")
	}
}

func TestFetchCredential_RejectsWrongProxyIdentity(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	token, _, err := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy-1", time.Minute)
	if err != nil {
		t.Fatalf("AuthorizeScope: %v", err)
	}
	if _, _, err := svc.FetchCredential(ctx, token, "database-proxy-1"); err == nil {
		t.Fatal("expected FetchCredential to reject a proxy identity different from the one authorized")
	}
}

func TestFetchCredential_ScopeTokenIsSingleUse(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	token, _, _ := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy-1", time.Minute)
	if _, _, err := svc.FetchCredential(ctx, token, "ssh-proxy-1"); err != nil {
		t.Fatalf("first FetchCredential should succeed: %v", err)
	}
	if _, _, err := svc.FetchCredential(ctx, token, "ssh-proxy-1"); err == nil {
		t.Fatal("expected a replayed scope token to be rejected (single-use)")
	}
}

func TestFetchCredential_ReturnsPlaintextMatchingOnboarded(t *testing.T) {
	svc := newTestService(t)
	ctx := context.Background()
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret-value"))
	token, _, _ := svc.AuthorizeScope(ctx, "session1", "acc1", "ssh-proxy-1", time.Minute)
	_, material, err := svc.FetchCredential(ctx, token, "ssh-proxy-1")
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
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("old-secret-value"))
	if err := svc.Rotate(ctx, adminRoles, "acc1", []byte("new-secret-value")); err != nil {
		t.Fatalf("Rotate: %v", err)
	}
	token, _, _ := svc.AuthorizeScope(ctx, "session2", "acc1", "ssh-proxy-1", time.Minute)
	_, material, err := svc.FetchCredential(ctx, token, "ssh-proxy-1")
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
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "prod-db-01-root", "root", "10.0.4.12:22", "ssh", domain.RotationManual, []byte("s3cret"))
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
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("old-secret-value"))
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate with no explicit secret: %v", err)
	}
	token, _, _ := svc.AuthorizeScope(ctx, "session2", "acc1", "ssh-proxy-1", time.Minute)
	_, material, err := svc.FetchCredential(ctx, token, "ssh-proxy-1")
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
	_ = svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial"))
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate 1: %v", err)
	}
	token1, _, _ := svc.AuthorizeScope(ctx, "s1", "acc1", "ssh-proxy-1", time.Minute)
	_, first, _ := svc.FetchCredential(ctx, token1, "ssh-proxy-1")
	if err := svc.Rotate(ctx, adminRoles, "acc1", nil); err != nil {
		t.Fatalf("Rotate 2: %v", err)
	}
	token2, _, _ := svc.AuthorizeScope(ctx, "s2", "acc1", "ssh-proxy-1", time.Minute)
	_, second, _ := svc.FetchCredential(ctx, token2, "ssh-proxy-1")
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
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true})
	ctx := context.Background()

	if err := svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("v1")); err != nil {
		t.Fatalf("OnboardAccount: %v", err)
	}
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

func TestOnboardAccount_EncryptedMaterialNeverContainsPlaintext(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatalf("kms: %v", err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true})
	ctx := context.Background()
	plaintext := []byte("a-very-identifiable-plaintext-marker")
	if err := svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, plaintext); err != nil {
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
	svc := application.NewVaultService(store, store, store, kms, authz)
	err := svc.OnboardAccount(context.Background(), []string{"nobody"}, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
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
	svc := application.NewVaultService(store, store, store, kms, authz)
	if err := svc.OnboardAccount(context.Background(), adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret")); err == nil {
		t.Fatal("expected OnboardAccount to fail closed when Authorization is unreachable")
	}
}

func TestRotate_DeniedWithoutAuthorization(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	permissive := &fakeAuthz{allowed: true}
	svc := application.NewVaultService(store, store, store, kms, permissive)
	ctx := context.Background()
	if err := svc.OnboardAccount(ctx, adminRoles, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("initial")); err != nil {
		t.Fatalf("onboarding setup: %v", err)
	}
	restrictive := &fakeAuthz{allowed: false, reason: "role lost admin rights"}
	svc2 := application.NewVaultService(store, store, store, kms, restrictive)
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
	svc := application.NewVaultService(store, store, store, kms, authz)
	err := svc.OnboardAccount(context.Background(), []string{"dba"}, "acc1", "target", "root", "10.0.0.1:22", "ssh", domain.RotationManual, []byte("s3cret"))
	if err == nil {
		t.Fatal("expected onboarding to be denied for a role with only session-creation rights")
	}
}

type sessionOnlyAuthz struct{}

func (sessionOnlyAuthz) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	if len(resource) >= len("vault:account:") && resource[:len("vault:account:")] == "vault:account:" {
		return true, "session-creation policy matched", nil
	}
	return false, "no policy matches this resource", nil
}

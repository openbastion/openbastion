package application_test

// The target's host key is pinned at the Vault (ADR-0039): no key, no secret — not to the
// proxy, not to a rotation — and a pin changes only for an administrator, audited first.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

func testFingerprint(t *testing.T) string {
	t.Helper()
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(testHostKey))
	if err != nil {
		t.Fatal(err)
	}
	return ssh.FingerprintSHA256(k)
}

func TestNormalizeHostKey_ReadsAKeyLineOrAKnownHostsLine_AndNothingElse(t *testing.T) {
	fp := testFingerprint(t)
	for name, in := range map[string]string{
		"a key":                    testHostKey,
		"a key with a comment":     testHostKey + " root@target",
		"surrounded by blanks":     "  " + testHostKey + "\n",
		"a known_hosts line":       "10.0.0.9 " + testHostKey,
		"a known_hosts line, port": "[10.0.0.9]:2222,target " + testHostKey,
		"a hashed known_hosts":     "|1|c2FsdA==|aGFzaA== " + testHostKey,
	} {
		key, got, err := application.NormalizeHostKey(in)
		if err != nil || key != testHostKey || got != fp {
			t.Fatalf("%s: (%q, %q, %v), want (%q, %q)", name, key, got, err, testHostKey, fp)
		}
	}
	for name, in := range map[string]string{
		"empty":             "",
		"blanks":            "   ",
		"not base64":        "ssh-ed25519 not-a-key",
		"a fingerprint":     fp,
		"two keys":          testHostKey + "\n" + testHostKey,
		"a private key":     "-----BEGIN OPENSSH PRIVATE KEY-----",
		"a type, no bytes":  "ssh-ed25519",
		"a revoked key":     "@revoked * " + testHostKey,
		"a CA key":          "@cert-authority *.example " + testHostKey,
		"a marker, no host": "@revoked " + testHostKey,
	} {
		if _, _, err := application.NormalizeHostKey(in); !errors.Is(err, application.ErrBadHostKey) {
			t.Fatalf("%s: accepted (%v)", name, err)
		}
	}
}

func pinnedService(t *testing.T) (*application.VaultService, *infrastructure.InMemoryStore, *fakeAuthz, *fakeAudit) {
	t.Helper()
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	authz, audit := &fakeAuthz{allowed: true}, &fakeAudit{}
	svc := application.NewVaultService(store, store, store, kms, authz).WithRotation(newFakeTarget(), audit)
	return svc, store, authz, audit
}

// Onboarding needs a key that reads; a refused one leaves no account behind.
func TestOnboardPinned_AKeyIsRequired_AndStoredAsRead(t *testing.T) {
	svc, store, _, _ := pinnedService(t)
	ctx := context.Background()
	for _, key := range []string{"", "nonsense"} {
		err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "acc", Name: "a", Username: "root", TargetHost: host,
			Protocol: "ssh", Policy: domain.RotationManual, InitialSecret: []byte("pw"), HostKey: key})
		if !errors.Is(err, application.ErrBadHostKey) {
			t.Fatalf("key %q: onboarding returned %v", key, err)
		}
		if _, err := store.Get(ctx, "acc"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("key %q: a refused onboarding left an account behind (%v)", key, err)
		}
	}
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "acc", Name: "a", Username: "root", TargetHost: host,
		Protocol: "ssh", Policy: domain.RotationManual, InitialSecret: []byte("pw"), HostKey: "  " + testHostKey + " root@target\n"}); err != nil {
		t.Fatal(err)
	}
	a, _ := store.Get(ctx, "acc")
	if a.HostKey != testHostKey {
		t.Fatalf("stored %q, want %q", a.HostKey, testHostKey)
	}
}

// An account without a pin (one onboarded before ADR-0039) is given no scope, no secret and
// no rotation. Counter-proof: pinned, it is given all three, the secret with its target.
func TestAnAccountWithoutAPin_GetsNoScopeNoSecretNoRotation(t *testing.T) {
	svc, store, target, _ := rotationService(t, domain.RotationManual)
	ctx := context.Background()
	scope, _, err := svc.AuthorizeScope(ctx, "s1", "acc", "ssh-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.SetHostKey(ctx, "acc", ""); err != nil { // as a migrated account is
		t.Fatal(err)
	}

	if _, _, err := svc.AuthorizeScope(ctx, "s2", "acc", "ssh-proxy", time.Minute); !errors.Is(err, application.ErrNoHostKey) {
		t.Fatalf("AuthorizeScope: %v", err)
	}
	if d, err := svc.FetchCredential(ctx, scope, "ssh-proxy"); !errors.Is(err, application.ErrNoHostKey) || d.Material != nil {
		t.Fatalf("FetchCredential of a scope granted before the pin went: %v, %d bytes", err, len(d.Material))
	}
	before := target.has(host, "app")
	if err := svc.Rotate(ctx, adminRoles, "acc", nil); !errors.Is(err, application.ErrNoHostKey) {
		t.Fatalf("Rotate: %v", err)
	}
	if target.has(host, "app") != before {
		t.Fatal("an unpinned rotation changed the target")
	}

	if _, err := svc.SetHostKey(ctx, "user_admin", adminRoles, "acc", testHostKey); err != nil {
		t.Fatal(err)
	}
	scope, _, err = svc.AuthorizeScope(ctx, "s3", "acc", "ssh-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	d, err := svc.FetchCredential(ctx, scope, "ssh-proxy")
	if err != nil || string(d.Material) != "old-pw" || d.HostKey != testHostKey || d.TargetHost != host {
		t.Fatalf("pinned: %v %+v", err, d)
	}
	if err := svc.Rotate(ctx, adminRoles, "acc", nil); err != nil {
		t.Fatalf("pinned rotation: %v", err)
	}
}

func TestSetHostKey_OnlyAnAdministrator_AuditedFirst(t *testing.T) {
	const other = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDtqJ7zOtqQtYqOo0CpvDXNlMhV3HeJDpjrASKGLWdop"
	svc, store, authz, audit := pinnedService(t)
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "acc", "a", "root", host, "ssh", domain.RotationManual, []byte("pw")); err != nil {
		t.Fatal(err)
	}
	pinned := func() string { a, _ := store.Get(ctx, "acc"); return a.HostKey }

	authz.allowed = false
	if _, err := svc.SetHostKey(ctx, "user_op", []string{"dba"}, "acc", other); err == nil || pinned() != testHostKey {
		t.Fatalf("a refused caller re-pinned: %v, key %q", err, pinned())
	}
	if authz.lastResource != "vault:account-admin:acc" || authz.lastAction != "vault:account:pin" {
		t.Fatalf("checked %s %s", authz.lastResource, authz.lastAction)
	}
	authz.allowed = true

	if _, err := svc.SetHostKey(ctx, "user_admin", adminRoles, "acc", "garbage"); !errors.Is(err, application.ErrBadHostKey) || pinned() != testHostKey {
		t.Fatalf("garbage: %v, key %q", err, pinned())
	}

	audit.down = true
	if _, err := svc.SetHostKey(ctx, "user_admin", adminRoles, "acc", other); err == nil || pinned() != testHostKey {
		t.Fatalf("re-pinned without the audit: %v, key %q", err, pinned())
	}
	audit.down = false

	fp, err := svc.SetHostKey(ctx, "user_admin", adminRoles, "acc", other)
	if err != nil || pinned() != other || !strings.HasPrefix(fp, "SHA256:") {
		t.Fatalf("re-pin: %v, key %q, fp %q", err, pinned(), fp)
	}
	if got := strings.Join(audit.events, ","); got != "user_admin|vault.host_key_set|acc|true" {
		t.Fatalf("audit: %s", got)
	}

	if err := svc.DisableAccount(ctx, adminRoles, "acc"); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.SetHostKey(ctx, "user_admin", adminRoles, "acc", testHostKey); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a disabled account was re-pinned: %v", err)
	}
}

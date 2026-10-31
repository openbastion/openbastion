package application_test

// Rotation reaches the target (ADR-0037).

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

const host = "10.0.0.9:22"

func rotationService(t *testing.T, policy domain.RotationPolicy) (*application.VaultService, *infrastructure.InMemoryStore, *fakeTarget, *fakeAudit) {
	t.Helper()
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	target, audit := newFakeTarget(), &fakeAudit{}
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(target, audit)
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "rec", "reconciliation", "root", host, "ssh", domain.RotationManual, []byte("root-pw")); err != nil {
		t.Fatal(err)
	}
	target.passwords[host+"|root"], target.passwords[host+"|app"] = "root-pw", "old-pw"
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "acc", Name: "app", Username: "app", TargetHost: host, Protocol: "ssh",
		Policy: policy, InitialSecret: []byte("old-pw"), ReconciliationAccountID: "rec", HostKey: testHostKey}); err != nil {
		t.Fatal(err)
	}
	return svc, store, target, audit
}

// injected is the secret the proxy would get for acc now.
func injected(t *testing.T, svc *application.VaultService) string {
	t.Helper()
	tok, _, err := svc.AuthorizeScope(context.Background(), fmt.Sprintf("s-%d", time.Now().UnixNano()), "acc", "ssh-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	secret, err := fetchMaterial(svc, context.Background(), tok, "ssh-proxy")
	if err != nil {
		t.Fatal(err)
	}
	return string(secret)
}

func TestRotate_ReachesTheTarget_AndWhatIsInjectedIsWhatTheTargetTakes(t *testing.T) {
	svc, _, target, audit := rotationService(t, domain.RotationManual)
	if err := svc.RotateAs(context.Background(), "user_alice", adminRoles, "acc", nil); err != nil {
		t.Fatal(err)
	}
	now := target.has(host, "app")
	if now == "old-pw" || now == "" {
		t.Fatalf("the target still has %q", now)
	}
	if got := injected(t, svc); got != now {
		t.Fatalf("injected %q, the target takes %q", got, now)
	}
	if fmt.Sprint(audit.events) != "[user_alice|vault.rotate_requested|acc|true user_alice|vault.rotate|acc|true]" {
		t.Fatalf("events %v", audit.events)
	}
	a, _ := svc.GetAccount(context.Background(), "acc")
	if a.LastRotatedAt == nil {
		t.Fatal("LastRotatedAt not set")
	}
}

func TestRotate_WithoutAReconciliationAccountIsRefused_AndNothingChanges(t *testing.T) {
	svc, _, target, audit := rotationService(t, domain.RotationManual)
	ctx := context.Background()
	_ = onboardTest(svc, ctx, adminRoles, "lonely", "lonely", "lonely", host, "ssh", domain.RotationManual, []byte("l-pw"))
	if err := svc.Rotate(ctx, adminRoles, "lonely", nil); !errors.Is(err, application.ErrNoReconciliation) {
		t.Fatalf("got %v, want ErrNoReconciliation", err)
	}
	if target.sets != 0 || len(audit.events) != 0 {
		t.Fatalf("%d changes on the target, events %v", target.sets, audit.events)
	}
	_ = onboardTest(svc, ctx, adminRoles, "elsewhere", "e", "root", "10.0.0.99:22", "ssh", domain.RotationManual, []byte("x"))
	for name, rec := range map[string]string{"itself": "lonely", "another target": "elsewhere", "no such account": "ghost"} {
		if err := svc.SetReconciliationAccount(ctx, adminRoles, "lonely", rec); !errors.Is(err, application.ErrNoReconciliation) {
			t.Fatalf("%s: %v", name, err)
		}
	}
	if err := svc.OnboardAccountWithReconciliation(ctx, adminRoles, "x2", "x", "x", host, "ssh", domain.RotationManual, []byte("x"), "elsewhere"); !errors.Is(err, application.ErrNoReconciliation) {
		t.Fatalf("onboarding with a reconciliation of another target: %v", err)
	}
	if _, err := svc.GetAccount(ctx, "x2"); err == nil {
		t.Fatal("the account was onboarded anyway")
	}
}

func TestRotate_TheTargetRefuses_NothingChanges(t *testing.T) {
	svc, store, target, audit := rotationService(t, domain.RotationManual)
	target.setFails = true
	if err := svc.Rotate(context.Background(), adminRoles, "acc", nil); !errors.Is(err, application.ErrRotationRefused) {
		t.Fatalf("got %v", err)
	}
	if got := injected(t, svc); got != "old-pw" {
		t.Fatalf("injected %q after a refused rotation, want the old secret", got)
	}
	if p, _ := store.PendingVersion(context.Background(), "acc"); p != nil {
		t.Fatal("a pending version left after the target refused")
	}
	if !strings.HasSuffix(fmt.Sprint(audit.events), "|vault.rotate|acc|false]") {
		t.Fatalf("events %v", audit.events)
	}
}

func TestRotate_SetButNotVerified_IsKeptPending_AndSettledByTheTargetNextTime(t *testing.T) {
	ctx := context.Background()
	t.Run("the new secret turns out to open the target: it becomes current", func(t *testing.T) {
		svc, store, target, _ := rotationService(t, domain.RotationManual)
		target.verifyBad = true
		if err := svc.Rotate(ctx, adminRoles, "acc", nil); !errors.Is(err, application.ErrRotationUnverified) {
			t.Fatalf("got %v", err)
		}
		if got := injected(t, svc); got != "old-pw" {
			t.Fatalf("injected %q while unverified, want the old secret", got)
		}
		pending, _ := store.PendingVersion(ctx, "acc")
		if pending == nil {
			t.Fatal("no pending version kept")
		}
		target.verifyBad = false
		target.setFails = true // the next rotation's own change fails: only the settling succeeds
		_ = svc.Rotate(ctx, adminRoles, "acc", nil)
		if got := injected(t, svc); got != target.has(host, "app") || got == "old-pw" {
			t.Fatalf("after settling: injected %q, the target takes %q", got, target.has(host, "app"))
		}
	})
	t.Run("the old secret still opens the target: the pending one is forgotten", func(t *testing.T) {
		svc, store, target, _ := rotationService(t, domain.RotationManual)
		target.verifyBad = true
		_ = svc.Rotate(ctx, adminRoles, "acc", nil)
		target.verifyBad = false
		target.passwords[host+"|app"] = "old-pw" // the change never took
		if err := svc.Rotate(ctx, adminRoles, "acc", nil); err != nil {
			t.Fatal(err)
		}
		if p, _ := store.PendingVersion(ctx, "acc"); p != nil {
			t.Fatal("still pending")
		}
		if got := injected(t, svc); got != target.has(host, "app") {
			t.Fatalf("injected %q, target %q", got, target.has(host, "app"))
		}
	})
	t.Run("neither opens it: nobody decides for a human", func(t *testing.T) {
		svc, _, target, _ := rotationService(t, domain.RotationManual)
		target.verifyBad = true
		_ = svc.Rotate(ctx, adminRoles, "acc", nil)
		if err := svc.Rotate(ctx, adminRoles, "acc", nil); !errors.Is(err, application.ErrRotationUnverified) || !strings.Contains(err.Error(), "human") {
			t.Fatalf("got %v", err)
		}
		if got := injected(t, svc); got != "old-pw" {
			t.Fatalf("injected %q", got)
		}
	})
}

func TestRotate_TheAuditDown_TheTargetIsNotTouched(t *testing.T) {
	svc, _, target, audit := rotationService(t, domain.RotationManual)
	audit.down = true
	if err := svc.Rotate(context.Background(), adminRoles, "acc", nil); err == nil || !strings.Contains(err.Error(), "audit") {
		t.Fatalf("got %v", err)
	}
	if target.sets != 0 || target.has(host, "app") != "old-pw" {
		t.Fatal("the target was changed with the audit down")
	}
}

func TestRotateAfterUse_OnlyAPostUseAccount(t *testing.T) {
	ctx := context.Background()
	svc, store, target, audit := rotationService(t, domain.RotationPostUse)
	res, err := svc.RotateAfterUse(ctx, "acc", time.Now())
	if err != nil || !res.Owed || !res.Rotated || target.has(host, "app") == "old-pw" {
		t.Fatalf("post_use: %+v %v", res, err)
	}
	if a, _ := store.Get(ctx, "acc"); a.RotationOwedSince != nil {
		t.Fatalf("a paid rotation is still owed: %v", a.RotationOwedSince)
	}
	if !strings.HasPrefix(fmt.Sprint(audit.events), "[|vault.rotate_requested|acc|true") {
		t.Fatalf("a rotation after use is a system action: %v", audit.events)
	}
	manual, _, target2, _ := rotationService(t, domain.RotationManual)
	if res, err := manual.RotateAfterUse(ctx, "acc", time.Now()); err != nil || res.Owed || target2.sets != 0 {
		t.Fatalf("manual: %+v %v, %d changes", res, err, target2.sets)
	}
}

func TestRotate_RefusedWhenTheTargetsCannotBeReached_AndForASecretThatCannotBeAPasswordLine(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true})
	_ = onboardTest(svc, context.Background(), adminRoles, "acc", "a", "app", host, "ssh", domain.RotationManual, []byte("x"))
	if err := svc.Rotate(context.Background(), adminRoles, "acc", nil); !errors.Is(err, application.ErrRotationOff) {
		t.Fatalf("got %v, want ErrRotationOff — no rotation that changes the Vault only", err)
	}
	rs, _, target, _ := rotationService(t, domain.RotationManual)
	for _, s := range []string{"a:b", "a\nroot:pwned"} {
		if err := rs.Rotate(context.Background(), adminRoles, "acc", []byte(s)); err == nil {
			t.Fatalf("secret %q accepted", s)
		}
	}
	if target.sets != 0 {
		t.Fatal("the target was changed")
	}
}

func TestPendingVersion_OnePerAccount(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	if err := store.AddPending(ctx, &domain.SecretVersion{PrivilegedAccountID: "a", Version: 2}); err != nil {
		t.Fatal(err)
	}
	if err := store.AddPending(ctx, &domain.SecretVersion{PrivilegedAccountID: "a", Version: 3}); !errors.Is(err, domain.ErrRotationInProgress) {
		t.Fatalf("a second pending version: %v", err)
	}
}

package application_test

// Scheduled rotations (ADR-0040): what is due rotates, by the path of ADR-0037; what is not
// due, not scheduled or disabled is left alone; a failure waits an hour; of two Vaults, one.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

// scheduledVault is a Vault with a reconciliation account "rec" and a scheduled account
// "acc" (user app, every 30 days) on host, its clock at *clock.
func scheduledVault(t *testing.T, clock *time.Time) (*application.VaultService, *infrastructure.InMemoryStore, *fakeTarget, *fakeAudit) {
	t.Helper()
	svc, store, target, audit, _ := scheduledVaultKMS(t, clock)
	return svc, store, target, audit
}

func scheduledVaultKMS(t *testing.T, clock *time.Time) (*application.VaultService, *infrastructure.InMemoryStore, *fakeTarget, *fakeAudit, application.Encryptor) {
	t.Helper()
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	target, audit := newFakeTarget(), &fakeAudit{}
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(target, audit).
		WithClock(func() time.Time { return *clock })
	ctx := context.Background()
	if err := onboardTest(svc, ctx, adminRoles, "rec", "reconciliation", "root", host, "ssh", domain.RotationManual, []byte("root-pw")); err != nil {
		t.Fatal(err)
	}
	target.passwords[host+"|root"], target.passwords[host+"|app"] = "root-pw", "old-pw"
	if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: "acc", Name: "app", Username: "app", TargetHost: host, Protocol: "ssh",
		Policy: domain.RotationScheduled, InitialSecret: []byte("old-pw"), ReconciliationAccountID: "rec", HostKey: testHostKey, RotationIntervalDays: 30}); err != nil {
		t.Fatal(err)
	}
	return svc, store, target, audit, kms
}

func TestOnboard_TheScheduleIsCheckedAtTheDoor(t *testing.T) {
	clock := time.Now()
	svc, store, _, _ := scheduledVault(t, &clock)
	ctx := context.Background()
	in := func(id string, policy domain.RotationPolicy, days int, rec string) application.OnboardInput {
		return application.OnboardInput{ID: id, Name: id, Username: id, TargetHost: host, Protocol: "ssh", Policy: policy,
			InitialSecret: []byte("pw"), ReconciliationAccountID: rec, HostKey: testHostKey, RotationIntervalDays: days}
	}
	for name, c := range map[string]application.OnboardInput{
		"scheduled, no interval":      in("a1", domain.RotationScheduled, 0, "rec"),
		"scheduled, a negative one":   in("a2", domain.RotationScheduled, -1, "rec"),
		"scheduled, more than a year": in("a3", domain.RotationScheduled, 366, "rec"),
		"manual, with an interval":    in("a4", domain.RotationManual, 7, "rec"),
		"post-use, with an interval":  in("a5", domain.RotationPostUse, 7, ""),
	} {
		if err := svc.OnboardPinned(ctx, adminRoles, c); !errors.Is(err, application.ErrBadRotationInterval) {
			t.Fatalf("%s: %v", name, err)
		}
		if _, err := store.Get(ctx, c.ID); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("%s: a refused onboarding left an account", name)
		}
	}
	if err := svc.OnboardPinned(ctx, adminRoles, in("a6", domain.RotationScheduled, 7, "")); !errors.Is(err, application.ErrNoReconciliation) {
		t.Fatalf("a scheduled account that could never rotate was onboarded: %v", err)
	}

	// Counter-proof: the bounds themselves are accepted, and the schedule is kept.
	for id, days := range map[string]int{"b1": 1, "b365": 365} {
		if err := svc.OnboardPinned(ctx, adminRoles, in(id, domain.RotationScheduled, days, "rec")); err != nil {
			t.Fatalf("%d days: %v", days, err)
		}
	}
	a, _ := store.Get(ctx, "acc")
	if a.RotationIntervalDays != 30 || a.HostKey != testHostKey || a.ReconciliationAccountID != "rec" {
		t.Fatalf("stored %+v", a)
	}
	if due := a.RotationDueAt(); due == nil || !due.Equal(a.CreatedAt.Add(30*24*time.Hour)) {
		t.Fatalf("due at %v, created %v", due, a.CreatedAt)
	}
}

func TestRotateDue_RotatesWhatIsDue_AsTheSystem_AndOnlyThat(t *testing.T) {
	clock := time.Now().Add(29 * 24 * time.Hour)
	svc, store, target, audit := scheduledVault(t, &clock)
	ctx := context.Background()
	// Beside it: accounts that no schedule concerns, and a disabled scheduled one.
	for _, o := range []struct {
		id     string
		policy domain.RotationPolicy
		days   int
	}{{"man", domain.RotationManual, 0}, {"use", domain.RotationPostUse, 0}, {"off", domain.RotationScheduled, 1}} {
		target.passwords[host+"|"+o.id] = o.id + "-pw"
		if err := svc.OnboardPinned(ctx, adminRoles, application.OnboardInput{ID: o.id, Name: o.id, Username: o.id, TargetHost: host, Protocol: "ssh",
			Policy: o.policy, InitialSecret: []byte(o.id + "-pw"), ReconciliationAccountID: "rec", HostKey: testHostKey, RotationIntervalDays: o.days}); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.DisableAccount(ctx, adminRoles, "off"); err != nil {
		t.Fatal(err)
	}

	// Day 29: nothing is due.
	if res, err := svc.RotateDue(ctx); err != nil || res.Rotated+res.Failed != 0 || target.has(host, "app") != "old-pw" {
		t.Fatalf("day 29: %+v %v, app=%q", res, err, target.has(host, "app"))
	}

	// Day 31: acc is due, and only acc rotates — on the target, verified, current, audited
	// as a system action (no actor).
	clock = time.Now().Add(31 * 24 * time.Hour)
	res, err := svc.RotateDue(ctx)
	if err != nil || res.Rotated != 1 || res.Failed != 0 {
		t.Fatalf("day 31: %+v %v", res, err)
	}
	newPw := target.has(host, "app")
	if newPw == "old-pw" || injected(t, svc) != newPw {
		t.Fatalf("the target has %q, the Vault injects %q", newPw, injected(t, svc))
	}
	for _, id := range []string{"man", "use", "off"} {
		if target.has(host, id) != id+"-pw" {
			t.Fatalf("%s was rotated", id)
		}
	}
	if got := strings.Join(audit.events, ","); got != "|vault.rotate_requested|acc|true,|vault.rotate|acc|true" {
		t.Fatalf("audit: %s", got)
	}
	if a, _ := store.Get(ctx, "acc"); a.LastRotatedAt == nil || a.RotationAttemptedAt == nil {
		t.Fatalf("after the rotation: %+v", a)
	}

	// The same sweep again does nothing: the account was just taken.
	if res, _ := svc.RotateDue(ctx); res.Rotated+res.Failed != 0 {
		t.Fatalf("a second sweep rotated again: %+v", res)
	}
}

func TestRotateDue_AFailureIsNotTriedAgainForAnHour(t *testing.T) {
	clock := time.Now().Add(31 * 24 * time.Hour)
	svc, _, target, audit := scheduledVault(t, &clock)
	ctx := context.Background()
	target.setFails = true

	res, err := svc.RotateDue(ctx)
	if err != nil || res.Failed != 1 || target.has(host, "app") != "old-pw" {
		t.Fatalf("a refused change: %+v %v", res, err)
	}
	events := len(audit.events)

	clock = clock.Add(59 * time.Minute)
	if res, _ := svc.RotateDue(ctx); res.Rotated+res.Failed != 0 || len(audit.events) != events {
		t.Fatalf("tried again within the hour: %+v, %d events", res, len(audit.events)-events)
	}

	// Counter-proof: after the hour, it is tried again, and the target now takes it.
	target.setFails = false
	clock = clock.Add(2 * time.Minute)
	if res, _ := svc.RotateDue(ctx); res.Rotated != 1 || target.has(host, "app") == "old-pw" {
		t.Fatalf("not tried again after the hour: %+v", res)
	}
}

func TestRotateDue_WithoutTheAudit_TheTargetIsNotTouched(t *testing.T) {
	clock := time.Now().Add(31 * 24 * time.Hour)
	svc, _, target, audit := scheduledVault(t, &clock)
	audit.down = true
	if res, _ := svc.RotateDue(context.Background()); res.Failed != 1 || target.sets != 0 {
		t.Fatalf("rotated without the audit: %+v, %d changes", res, target.sets)
	}
}

// Two Vaults on one store sweep at the same moment: the account rotates once.
func TestRotateDue_TwoVaultsAtOnce_RotateTheAccountOnce(t *testing.T) {
	clock := time.Now().Add(31 * 24 * time.Hour)
	svc, store, target, audit, kms := scheduledVaultKMS(t, &clock)
	other := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true}).WithRotation(target, audit).
		WithClock(func() time.Time { return clock })
	var wg sync.WaitGroup
	results := make([]application.SweepResult, 2)
	for i, v := range []*application.VaultService{svc, other} {
		wg.Add(1)
		go func(i int, v *application.VaultService) {
			defer wg.Done()
			results[i], _ = v.RotateDue(context.Background())
		}(i, v)
	}
	wg.Wait()
	if results[0].Rotated+results[1].Rotated != 1 || target.sets != 1 {
		t.Fatalf("results %+v, %d changes on the target", results, target.sets)
	}
}

func TestRotateDue_WithoutRotation_IsOff(t *testing.T) {
	kms, _ := infrastructure.NewLocalKMS()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, &fakeAuthz{allowed: true})
	if _, err := svc.RotateDue(context.Background()); !errors.Is(err, application.ErrRotationOff) {
		t.Fatalf("%v", err)
	}
}

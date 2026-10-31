package application_test

// ADR-0044: a rotation after use is a debt the Vault records before paying, and pays to the end.

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

func TestRotateAfterUse_AFailureStaysOwed_AndASweepPaysIt(t *testing.T) {
	ctx := context.Background()
	svc, store, target, audit := rotationService(t, domain.RotationPostUse)
	clock := time.Now()
	svc.WithClock(func() time.Time { return clock })
	target.setFails = true

	res, err := svc.RotateAfterUse(ctx, "acc", clock)
	if err != nil || !res.Owed || res.Rotated {
		t.Fatalf("a refused change: %+v %v (the Broker must be told it is recorded)", res, err)
	}
	a, _ := store.Get(ctx, "acc")
	if a.RotationOwedSince == nil || a.RotationFailures != 1 {
		t.Fatalf("not recorded: owed %v, %d failures", a.RotationOwedSince, a.RotationFailures)
	}

	// Within the hour, the sweep leaves it; after it, the target takes it and the debt is paid.
	target.setFails = false
	clock = clock.Add(30 * time.Minute)
	if r, _ := svc.RotateDue(ctx); r.Rotated != 0 {
		t.Fatalf("tried again within the hour: %+v", r)
	}
	clock = clock.Add(31 * time.Minute)
	if r, _ := svc.RotateDue(ctx); r.Rotated != 1 || target.has(host, "app") == "old-pw" {
		t.Fatalf("the sweep did not pay it: %+v", r)
	}
	if a, _ := store.Get(ctx, "acc"); a.RotationOwedSince != nil || a.RotationFailures != 0 {
		t.Fatalf("after payment: owed %v, %d failures", a.RotationOwedSince, a.RotationFailures)
	}
	if n := countEvents(audit.events, "|vault.rotate|acc|true"); n != 1 {
		t.Fatalf("%d successful rotations audited, want 1", n)
	}
}

func countEvents(events []string, e string) int {
	n := 0
	for _, x := range events {
		if x == e {
			n++
		}
	}
	return n
}

// The same notice twice — two Brokers, a resend — rotates once.
func TestRotateAfterUse_ARepeatedNoticeRotatesOnce(t *testing.T) {
	ctx := context.Background()
	svc, _, target, _ := rotationService(t, domain.RotationPostUse)
	ended := time.Now().Add(-time.Second)
	if res, err := svc.RotateAfterUse(ctx, "acc", ended); err != nil || !res.Rotated {
		t.Fatalf("first notice: %+v %v", res, err)
	}
	sets := target.sets
	if res, err := svc.RotateAfterUse(ctx, "acc", ended); err != nil || res.Owed || target.sets != sets {
		t.Fatalf("the same notice again: %+v %v, %d more changes", res, err, target.sets-sets)
	}
	// Counter-proof: a later use is owed again.
	if res, _ := svc.RotateAfterUse(ctx, "acc", time.Now().Add(time.Second)); !res.Owed || !res.Rotated {
		t.Fatalf("a later use: %+v", res)
	}
}

// The window holds scheduled rotations, not a debt after use (ADR-0044).
func TestRotateDue_ADebtIsPaidOutsideTheWindow_AScheduleWaits(t *testing.T) {
	ctx := context.Background()
	svc, store, target, _ := rotationService(t, domain.RotationPostUse)
	clock := time.Date(2026, 12, 15, 14, 0, 0, 0, time.UTC)
	svc.WithClock(func() time.Time { return clock })
	w, _ := application.ParseRotationWindow("02:00-05:00")
	if _, err := svc.WithRotationSchedule(w, 3); err != nil {
		t.Fatal(err)
	}
	if err := store.MarkRotationOwed(ctx, "acc", clock.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	res, err := svc.RotateDue(ctx)
	if err != nil || !res.OutsideWindow || res.Rotated != 1 || target.has(host, "app") == "old-pw" {
		t.Fatalf("outside the window: %+v %v", res, err)
	}
}

func TestMarkRotationOwed_KeepsTheEarliest(t *testing.T) {
	ctx := context.Background()
	_, store, _, _ := rotationService(t, domain.RotationPostUse)
	early, late := time.Now().Add(-2*time.Hour), time.Now()
	_ = store.MarkRotationOwed(ctx, "acc", late)
	_ = store.MarkRotationOwed(ctx, "acc", early)
	_ = store.MarkRotationOwed(ctx, "acc", late)
	if a, _ := store.Get(ctx, "acc"); a.RotationOwedSince == nil || !a.RotationOwedSince.Equal(early) {
		t.Fatalf("owed since %v, want %v", a.RotationOwedSince, early)
	}
}

// A debt already owed, and failing, keeps its delay: a target that is down is not tried at every
// session that ends.
func TestRotateAfterUse_AFailingDebtKeepsItsDelay(t *testing.T) {
	ctx := context.Background()
	svc, _, target, _ := rotationService(t, domain.RotationPostUse)
	target.setFails = true
	if res, _ := svc.RotateAfterUse(ctx, "acc", time.Now()); !res.Owed || res.Rotated {
		t.Fatalf("first: %+v", res)
	}
	target.setFails = false
	if res, _ := svc.RotateAfterUse(ctx, "acc", time.Now().Add(time.Second)); !res.Owed || res.Rotated || target.sets != 0 {
		t.Fatalf("a second session's end tried again at once: %+v, %d changes", res, target.sets)
	}
}

package application_test

// ADR-0041: failed scheduled rotations are counted and, every N in a row, written to the audit
// as vault.rotation_overdue; a success sets the count back; a window keeps the sweep to its hours.

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
)

func TestParseRotationWindow(t *testing.T) {
	at := func(hm string) time.Time {
		v, _ := time.Parse("15:04", hm)
		return time.Date(2026, 10, 30, v.Hour(), v.Minute(), 0, 0, time.UTC)
	}
	w, err := application.ParseRotationWindow("02:00-05:00")
	if err != nil {
		t.Fatal(err)
	}
	for hm, in := range map[string]bool{"01:59": false, "02:00": true, "04:59": true, "05:00": false, "14:00": false} {
		if w.Contains(at(hm)) != in {
			t.Fatalf("02:00-05:00 contains %s: %v", hm, !in)
		}
	}
	night, err := application.ParseRotationWindow("22:30-03:00")
	if err != nil {
		t.Fatal(err)
	}
	for hm, in := range map[string]bool{"22:29": false, "22:30": true, "23:59": true, "00:00": true, "02:59": true, "03:00": false, "12:00": false} {
		if night.Contains(at(hm)) != in {
			t.Fatalf("22:30-03:00 contains %s: %v", hm, !in)
		}
	}
	// Compared in UTC whatever the zone given: 06:00 in UTC+2 is 04:00 UTC (in), 03:00 in
	// UTC+2 is 01:00 UTC (out) — the opposite of their local hours.
	plus2 := time.FixedZone("UTC+2", 2*3600)
	if !w.Contains(time.Date(2026, 10, 30, 6, 0, 0, 0, plus2)) || w.Contains(time.Date(2026, 10, 30, 3, 0, 0, 0, plus2)) {
		t.Fatal("the window is not compared in UTC")
	}
	any, err := application.ParseRotationWindow("")
	if err != nil || !any.Contains(at("13:37")) || any.String() != "any time" {
		t.Fatalf("no window: %v %v", err, any)
	}
	for _, bad := range []string{"2:00-5:00", "02:00", "02:00-02:00", "24:00-01:00", "02:60-03:00", "aa:bb-cc:dd", "02:00-05:00-06:00", "02:00 05:00"} {
		if _, err := application.ParseRotationWindow(bad); err == nil {
			t.Fatalf("%q was accepted", bad)
		}
	}
}

func TestRotateDue_OutsideTheWindow_NothingIsTaken(t *testing.T) {
	clock := time.Date(2026, 12, 15, 14, 0, 0, 0, time.UTC) // well past due, at 14:00 UTC
	svc, store, target, audit := scheduledVault(t, &clock)
	w, _ := application.ParseRotationWindow("02:00-05:00")
	if _, err := svc.WithRotationSchedule(w, 3); err != nil {
		t.Fatal(err)
	}
	res, err := svc.RotateDue(context.Background())
	if err != nil || !res.OutsideWindow || res.Rotated+res.Failed != 0 || target.sets != 0 || len(audit.events) != 0 {
		t.Fatalf("outside the window: %+v %v, %d changes, %v", res, err, target.sets, audit.events)
	}
	if a, _ := store.Get(context.Background(), "acc"); a.RotationAttemptedAt != nil {
		t.Fatal("an account was taken outside the window")
	}
	// Counter-proof: at 03:00 UTC the same account rotates.
	clock = time.Date(2026, 12, 16, 3, 0, 0, 0, time.UTC)
	if res, _ := svc.RotateDue(context.Background()); res.Rotated != 1 {
		t.Fatalf("inside the window: %+v", res)
	}
}

func TestWithRotationSchedule_TheThresholdIsBounded(t *testing.T) {
	clock := time.Now()
	svc, _, _, _ := scheduledVault(t, &clock)
	for _, n := range []int{0, -1, application.MaxRotationAlertAfter + 1} {
		if _, err := svc.WithRotationSchedule(application.RotationWindow{}, n); err == nil {
			t.Fatalf("%d was accepted", n)
		}
	}
}

func TestRotateDue_FailuresInARowRaiseAnAlert_EveryNth_AndASuccessResetsThem(t *testing.T) {
	clock := time.Now().Add(31 * 24 * time.Hour)
	svc, store, target, audit := scheduledVault(t, &clock)
	if _, err := svc.WithRotationSchedule(application.RotationWindow{}, 2); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	target.setFails = true
	alerts := func() int { // whole events: the alert is the system's, with no actor
		n := 0
		for _, e := range audit.events {
			if e == "|vault.rotation_overdue|acc|false" {
				n++
			}
		}
		return n
	}
	sweep := func() {
		t.Helper()
		if _, err := svc.RotateDue(ctx); err != nil {
			t.Fatal(err)
		}
		clock = clock.Add(61 * time.Minute)
	}

	sweep()
	if a, _ := store.Get(ctx, "acc"); a.RotationFailures != 1 || alerts() != 0 {
		t.Fatalf("after 1 failure: %d failures, %d alerts", a.RotationFailures, alerts())
	}
	sweep()
	if a, _ := store.Get(ctx, "acc"); a.RotationFailures != 2 || alerts() != 1 {
		t.Fatalf("after 2 failures: %d failures, %d alerts", a.RotationFailures, alerts())
	}
	sweep()
	if alerts() != 1 {
		t.Fatalf("after 3 failures: %d alerts, want still 1", alerts())
	}
	// The audit is down at the 4th: the alert is lost, and written again at the 6th.
	audit.down = true
	sweep()
	audit.down = false
	if alerts() != 1 {
		t.Fatalf("an alert was written with the audit down")
	}
	sweep()
	sweep()
	if a, _ := store.Get(ctx, "acc"); a.RotationFailures != 6 || alerts() != 2 {
		t.Fatalf("after 6 failures: %d failures, %d alerts", a.RotationFailures, alerts())
	}

	// A success sets the count back to 0.
	target.setFails = false
	if res, _ := svc.RotateDue(ctx); res.Rotated != 1 {
		t.Fatalf("the target takes it again: %+v", res)
	}
	if a, _ := store.Get(ctx, "acc"); a.RotationFailures != 0 {
		t.Fatalf("after a success: %d failures", a.RotationFailures)
	}
}

// A manual rotation that succeeds sets the count back as well.
func TestRotate_AManualSuccessResetsTheFailures(t *testing.T) {
	clock := time.Now().Add(31 * 24 * time.Hour)
	svc, store, target, _ := scheduledVault(t, &clock)
	target.setFails = true
	_, _ = svc.RotateDue(context.Background())
	target.setFails = false
	if err := svc.Rotate(context.Background(), adminRoles, "acc", nil); err != nil {
		t.Fatal(err)
	}
	if a, _ := store.Get(context.Background(), "acc"); a.RotationFailures != 0 {
		t.Fatalf("%d failures after a manual rotation", a.RotationFailures)
	}
}

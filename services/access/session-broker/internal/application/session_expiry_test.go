package application_test

// Expiring the sessions and requests past their end, and writing each expiry (ADR-0034).

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type expiryAudit struct {
	events []string
	down   bool
}

func (a *expiryAudit) EmitEvent(_ context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	if a.down {
		return errors.New("audit unreachable")
	}
	a.events = append(a.events, fmt.Sprintf("%s|%s|%s|%s|%v", actorID, action, resourceType, resourceID, success))
	return nil
}

func expiringBroker(t *testing.T, now time.Time) (*application.SessionBrokerService, *infrastructure.InMemoryStore, *expiryAudit) {
	t.Helper()
	store := infrastructure.NewInMemoryStore()
	audit := &expiryAudit{}
	for _, s := range []struct {
		id     string
		status domain.SessionStatus
		end    time.Time
	}{
		{"s_unused", domain.StatusActive, now.Add(-time.Minute)},
		{"s_request", domain.StatusPendingApproval, now.Add(-time.Second)},
		{"s_running", domain.StatusActive, now.Add(time.Hour)},
		{"s_terminated", domain.StatusTerminated, now.Add(-time.Hour)},
	} {
		_ = store.Save(context.Background(), &domain.Session{ID: s.id, Status: s.status, Protocol: "ssh", RequestedBy: "u",
			PrivilegedAccountID: "acc", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: s.end})
	}
	svc := application.NewSessionBrokerService(store, &fakeAuthz{}, &fakeVaultAuthorizer{}, audit, &fakeAccountLookup{}, &fakeProxyClient{})
	return svc.WithClock(func() time.Time { return now }), store, audit
}

func TestExpireDue_ExpiresWhatIsPastItsEnd_AndWritesEachAsASystemAction(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	svc, store, audit := expiringBroker(t, now)
	expired, written, err := svc.ExpireDue(context.Background())
	if err != nil || expired != 2 || written != 2 {
		t.Fatalf("ExpireDue: %d expired, %d written, %v; want 2, 2", expired, written, err)
	}
	want := "[|session.expire|session|s_unused|true |session.expire|session|s_request|true]"
	if got := fmt.Sprint(audit.events); got != want {
		t.Fatalf("events %s, want %s — no actor: the system expires", got, want)
	}
	for id, st := range map[string]domain.SessionStatus{"s_unused": domain.StatusExpired, "s_request": domain.StatusExpired, "s_running": domain.StatusActive, "s_terminated": domain.StatusTerminated} {
		if s, _ := store.Get(context.Background(), id); s.Status != st {
			t.Fatalf("%s: %s, want %s", id, s.Status, st)
		}
	}
	if e, w, _ := svc.ExpireDue(context.Background()); e != 0 || w != 0 || len(audit.events) != 2 {
		t.Fatalf("a second sweep expired %d and wrote %d: each expiry once", e, w)
	}
}

func TestExpireDue_TheAuditDown_TheExpiriesWait_AndAreWrittenOnceAtTheNextSweep(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	svc, store, audit := expiringBroker(t, now)
	audit.down = true
	expired, written, err := svc.ExpireDue(context.Background())
	if err == nil || expired != 2 || written != 0 {
		t.Fatalf("audit down: %d expired, %d written, %v; want 2 expired, 0 written, an error", expired, written, err)
	}
	if s, _ := store.Get(context.Background(), "s_unused"); s.Status != domain.StatusExpired {
		t.Fatal("what is past its end is expired whether or not the audit answers")
	}
	audit.down = false
	if _, written, err := svc.ExpireDue(context.Background()); err != nil || written != 2 {
		t.Fatalf("audit back: wrote %d, %v; want the two expiries, at once, not after the grace", written, err)
	}
	if _, written, _ := svc.ExpireDue(context.Background()); written != 0 || len(audit.events) != 2 {
		t.Fatalf("wrote %d more, %d in all: once each", written, len(audit.events))
	}
}

func TestExpireDue_WritesWhatAnotherReplicaLeft_AfterTheGrace(t *testing.T) {
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	_, store, _ := expiringBroker(t, now)
	// Another replica expired these and stopped before writing them.
	if _, err := store.ExpireDue(context.Background(), now, 10); err != nil {
		t.Fatal(err)
	}
	audit := &expiryAudit{}
	at := now
	svc := application.NewSessionBrokerService(store, &fakeAuthz{}, &fakeVaultAuthorizer{}, audit, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithClock(func() time.Time { return at })
	if _, written, _ := svc.ExpireDue(context.Background()); written != 0 {
		t.Fatalf("within the grace, wrote %d: what another replica may be writing is left to it", written)
	}
	at = now.Add(application.ExpiryAuditGrace + time.Second)
	if _, written, err := svc.ExpireDue(context.Background()); err != nil || written != 2 {
		t.Fatalf("after the grace: wrote %d, %v; want 2", written, err)
	}
}

// A service built by hand, with no clock given, sweeps on the system clock.
func TestExpireDue_NeedsNoClockToBeGiven(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	_ = store.Save(context.Background(), &domain.Session{ID: "s", Status: domain.StatusActive, ExpiresAt: time.Now().Add(-time.Minute)})
	svc := application.NewSessionBrokerService(store, &fakeAuthz{}, &fakeVaultAuthorizer{}, &expiryAudit{}, &fakeAccountLookup{}, &fakeProxyClient{})
	if expired, _, err := svc.ExpireDue(context.Background()); err != nil || expired != 1 {
		t.Fatalf("%d expired, %v", expired, err)
	}
}

package application_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// alertRecorder is an AlertNotifier that keeps what it was given.
type alertRecorder struct {
	mu     sync.Mutex
	events []domain.Event
}

func (r *alertRecorder) Notify(_ context.Context, e domain.Event) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.events = append(r.events, e)
}

func (r *alertRecorder) got() []domain.Event {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]domain.Event(nil), r.events...)
}

// failingStore refuses every append.
type failingStore struct{ *infrastructure.InMemoryStore }

func (failingStore) Append(context.Context, *domain.Event) error { return errors.New("disk full") }

func TestAlerts_AnAlertWrittenByItsEmitterIsPushed_AsItWasWritten(t *testing.T) {
	ctx := context.Background()
	rec := &alertRecorder{}
	svc := application.NewAuditService(infrastructure.NewInMemoryStore()).WithAlertNotifier(rec, false)

	e, err := svc.EmitEventAs(ctx, mtls.PasswordVault, "", "vault.rotation_overdue", "account", "acc_1", false)
	if err != nil {
		t.Fatal(err)
	}
	got := rec.got()
	if len(got) != 1 {
		t.Fatalf("%d alerts pushed, want 1", len(got))
	}
	if got[0].ID != e.ID || got[0].Action != "vault.rotation_overdue" || got[0].ResourceID != "acc_1" || got[0].Emitter != mtls.PasswordVault || len(got[0].Hash) == 0 {
		t.Fatalf("the pushed alert is not the event written: %+v", got[0])
	}
}

func TestAlerts_AnotherServiceCannotRaiseTheVaultsAlert(t *testing.T) {
	// The attack: a compromised Broker, Proxy or Recorder — each may write to the trail —
	// writes vault.rotation_overdue to page the on-call, or to drown a real alert. The event is
	// in the chain, as every write is; it is not pushed.
	ctx := context.Background()
	rec := &alertRecorder{}
	svc := application.NewAuditService(infrastructure.NewInMemoryStore()).WithAlertNotifier(rec, false)
	for _, emitter := range []string{mtls.SessionBroker, mtls.SSHProxy, mtls.CommandRecorder, ""} {
		if _, err := svc.EmitEventAs(ctx, emitter, "", "vault.rotation_overdue", "account", "acc_1", false); err != nil {
			t.Fatalf("%q: %v", emitter, err)
		}
	}
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("%d alerts pushed for emitters that may not raise it: %+v", len(got), got)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("the writes must still be in the chain: %v", err)
	}
}

func TestAlerts_WithoutInternalTLSNoEmitterIsNamed_AndTheAlertIsPushedOnlyIfAllowed(t *testing.T) {
	ctx := context.Background()
	rec := &alertRecorder{}
	svc := application.NewAuditService(infrastructure.NewInMemoryStore()).WithAlertNotifier(rec, true)
	if _, err := svc.EmitEvent(ctx, "", "vault.rotation_overdue", "account", "acc_1", false); err != nil {
		t.Fatal(err)
	}
	if len(rec.got()) != 1 {
		t.Fatalf("with no emitter named and the service told so, the alert is pushed")
	}
	// Allowed to be unnamed does not let a named stranger through.
	if _, err := svc.EmitEventAs(ctx, mtls.SessionBroker, "", "vault.rotation_overdue", "account", "acc_1", false); err != nil {
		t.Fatal(err)
	}
	if len(rec.got()) != 1 {
		t.Fatalf("a named emitter other than the Vault was pushed")
	}
}

func TestAlerts_WhatIsNotAnAlertIsNotPushed(t *testing.T) {
	ctx := context.Background()
	rec := &alertRecorder{}
	svc := application.NewAuditService(infrastructure.NewInMemoryStore()).WithAlertNotifier(rec, true)
	for _, action := range []string{"vault.rotate", "vault.rotation_overdue_x", "session.expire", "vault.rotation"} {
		if _, err := svc.EmitEventAs(ctx, mtls.PasswordVault, "", action, "account", "acc_1", false); err != nil {
			t.Fatal(err)
		}
	}
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("%d events pushed that are not alerts: %+v", len(got), got)
	}
}

func TestAlerts_AnAlertTheChainRefusedIsNeverPushed(t *testing.T) {
	ctx := context.Background()
	rec := &alertRecorder{}
	svc := application.NewAuditService(failingStore{infrastructure.NewInMemoryStore()}).WithAlertNotifier(rec, false)
	if _, err := svc.EmitEventAs(ctx, mtls.PasswordVault, "", "vault.rotation_overdue", "account", "acc_1", false); err == nil {
		t.Fatal("the append was expected to fail")
	}
	// And one the bounds refuse (ADR-0025) is not either.
	if _, err := svc.EmitEventAs(ctx, mtls.PasswordVault, "", "vault.rotation_overdue", "account", "", false); err == nil {
		t.Fatal("an event without a resource id was expected to be refused")
	}
	if got := rec.got(); len(got) != 0 {
		t.Fatalf("%d alerts pushed that are not in the chain", len(got))
	}
}

func TestAlerts_WithoutANotifierNothingChanges(t *testing.T) {
	svc := application.NewAuditService(infrastructure.NewInMemoryStore())
	if _, err := svc.EmitEventAs(context.Background(), mtls.PasswordVault, "", "vault.rotation_overdue", "account", "acc_1", false); err != nil {
		t.Fatal(err)
	}
}

func TestAlerts_EachAlertIsRaisedByAServiceThatExists(t *testing.T) {
	got := application.AlertActions()
	if got["vault.rotation_overdue"] != mtls.PasswordVault {
		t.Fatalf("vault.rotation_overdue is raised by %q, want %q", got["vault.rotation_overdue"], mtls.PasswordVault)
	}
	for action, emitter := range got {
		if !mtls.ValidServiceName(emitter) {
			t.Fatalf("%s names %q, which is not a service name", action, emitter)
		}
	}
}

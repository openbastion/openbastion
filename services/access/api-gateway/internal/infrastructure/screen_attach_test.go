package infrastructure_test

import (
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
)

func TestScreenAttachRegistryIsSessionBoundAndSingleUse(t *testing.T) {
	r := infrastructure.NewScreenAttachRegistry()
	now := time.Now()
	token, err := r.Register(infrastructure.ScreenAttach{SessionID: "session-a", UserID: "operator-a", Endpoint: "proxy:8090", Ticket: "secret-ticket", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Consume(token, "session-b", now); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("cross-session attach error=%v", err)
	}
	if got, err := r.Consume(token, "session-a", now); err != nil || got.SessionID != "session-a" {
		t.Fatalf("cross-session attempt consumed or damaged token: attach=%#v err=%v", got, err)
	}
	r.ReleaseSession("session-a")
	if _, err := r.Consume(token, "session-a", now); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("replay error=%v", err)
	}
	second, err := r.Register(infrastructure.ScreenAttach{SessionID: "session-a", UserID: "operator-a", Endpoint: "proxy:8090", Ticket: "secret-ticket", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	got, err := r.Consume(second, "session-a", now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Ticket != "secret-ticket" {
		t.Fatal("ticket was not retained for the one upstream dial")
	}
	r.ReleaseSession("session-a")
	if _, err := r.Consume(second, "session-a", now); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("replay error=%v", err)
	}
}

func TestScreenAttachRegistryRejectsExpiredAttach(t *testing.T) {
	r := infrastructure.NewScreenAttachRegistry()
	now := time.Now()
	token, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "operator-a", Endpoint: "proxy:8090", Ticket: "t", ExpiresAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Consume(token, "s", now); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("expired attach error=%v", err)
	}
}

func TestScreenAttachRegistryAllowsOneActiveSocketPerSession(t *testing.T) {
	r := infrastructure.NewScreenAttachRegistry()
	now := time.Now()
	token, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "u", Endpoint: "proxy:8090", Ticket: "t", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Consume(token, "s", now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "u", Endpoint: "proxy:8090", Ticket: "t2", ExpiresAt: now.Add(time.Minute)}); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("parallel attach registration error=%v", err)
	}
	r.ReleaseSession("s")
	if _, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "u", Endpoint: "proxy:8090", Ticket: "t3", ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatalf("registration after disconnect: %v", err)
	}
}

func TestScreenAttachRegistryLimitsUpgradesPerUser(t *testing.T) {
	r := infrastructure.NewScreenAttachRegistry()
	now := time.Now()
	for i := 0; i < 10; i++ {
		if !r.AllowUpgrade("operator", now) {
			t.Fatalf("upgrade %d unexpectedly refused", i+1)
		}
	}
	if r.AllowUpgrade("operator", now) {
		t.Fatal("11th upgrade in one minute was allowed")
	}
	if !r.AllowUpgrade("another-operator", now) {
		t.Fatal("rate limit leaked across users")
	}
	if !r.AllowUpgrade("operator", now.Add(time.Minute)) {
		t.Fatal("upgrade budget did not reset after a minute")
	}
}

func TestScreenAttachRegistryReplacesOlderPendingTicketForSameSession(t *testing.T) {
	r := infrastructure.NewScreenAttachRegistry()
	now := time.Now()
	first, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "u", Endpoint: "proxy:8090", Ticket: "ticket-one", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := r.Register(infrastructure.ScreenAttach{SessionID: "s", UserID: "u", Endpoint: "proxy:8090", Ticket: "ticket-two", ExpiresAt: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := r.Consume(first, "s", now); !errors.Is(err, infrastructure.ErrScreenAttachInvalid) {
		t.Fatalf("older pending ticket remained usable: %v", err)
	}
	attach, err := r.Consume(second, "s", now)
	if err != nil {
		t.Fatal(err)
	}
	if attach.Ticket != "ticket-two" {
		t.Fatalf("ticket=%q, want newest ticket", attach.Ticket)
	}
	r.ReleaseSession("s")
}

package infrastructure_test

import (
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
)

func TestPendingSessions_ConsumeRejectsUnknownTicket(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	if _, err := p.Consume("never-registered"); err == nil {
		t.Fatal("expected Consume to reject an unregistered ticket")
	}
}

func TestPendingSessions_ConsumeIsSingleUse(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	ticket := p.Register(&infrastructure.PendingSession{
		SessionID: "s1", TargetHost: "10.0.0.1:22", TargetUser: "root",
		ScopeToken: "scope1", ExpiresAt: time.Now().UTC().Add(time.Minute),
	})

	if _, err := p.Consume(ticket); err != nil {
		t.Fatalf("first Consume should succeed: %v", err)
	}
	if _, err := p.Consume(ticket); err == nil {
		t.Fatal("expected a reused ticket to be rejected — connection tickets are single-use")
	}
}

func TestPendingSessions_ConsumeRejectsExpiredTicket(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	ticket := p.Register(&infrastructure.PendingSession{
		SessionID: "s1", TargetHost: "10.0.0.1:22", TargetUser: "root",
		ScopeToken: "scope1", ExpiresAt: time.Now().UTC().Add(-time.Second), // already expired
	})

	if _, err := p.Consume(ticket); err == nil {
		t.Fatal("expected an expired ticket to be rejected")
	}
}

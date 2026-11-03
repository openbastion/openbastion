package infrastructure_test

import (
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

func TestPendingScreenSessions_TicketIsSingleUseAndExpiresStrictly(t *testing.T) {
	p := infrastructure.NewPendingScreenSessions()
	now := time.Now().UTC()
	want := infrastructure.PendingScreenSession{SessionID: "s1", ScopeToken: "one-use-scope", Protocol: screenstream.ProtocolVNC, ExpiresAt: now.Add(time.Minute)}
	ticket, err := p.Register(want)
	if err != nil {
		t.Fatal(err)
	}
	got, err := p.Consume(ticket, now)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("consumed session = %#v, want %#v", got, want)
	}
	if _, err := p.Consume(ticket, now); !errors.Is(err, infrastructure.ErrInvalidScreenTicket) {
		t.Fatalf("replay error = %v", err)
	}
	expired, err := p.Register(infrastructure.PendingScreenSession{SessionID: "s2", ScopeToken: "scope", Protocol: screenstream.ProtocolVNC, ExpiresAt: now})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.Consume(expired, now); !errors.Is(err, infrastructure.ErrInvalidScreenTicket) {
		t.Fatalf("expired ticket error = %v", err)
	}
}

func TestPendingScreenSessions_RevokeDropsOnlyMatchingSession(t *testing.T) {
	p := infrastructure.NewPendingScreenSessions()
	now := time.Now().UTC()
	for _, id := range []string{"a", "b", "a"} {
		if _, err := p.Register(infrastructure.PendingScreenSession{SessionID: id, ScopeToken: "scope", Protocol: screenstream.ProtocolVNC, ExpiresAt: now.Add(time.Minute)}); err != nil {
			t.Fatal(err)
		}
	}
	if got := p.RevokeSession("a"); got != 2 {
		t.Fatalf("revoked %d tickets, want 2", got)
	}
	if got := p.RevokeSession("missing"); got != 0 {
		t.Fatalf("revoked %d tickets for unknown session", got)
	}
}

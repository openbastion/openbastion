package infrastructure_test

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
)

func register(p *infrastructure.PendingSessions, session string) string {
	return p.Register(&infrastructure.PendingSession{SessionID: session, TargetHost: "10.0.0.5:22", ScopeToken: "scope-" + session, ExpiresAt: time.Now().Add(time.Hour)})
}

// A ticket is the only way to open a connection: one that was revoked opens nothing, and the
// others — of other sessions, and of the same operator — are not touched (ADR-0018).
func TestPendingSessions_RevokeSessionDropsEveryTicketOfThatSession_AndOnlyThose(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	a1, a2 := register(p, "A"), register(p, "A")
	b := register(p, "B")

	if n := p.RevokeSession("A"); n != 2 {
		t.Fatalf("revoked %d tickets of A, want 2", n)
	}
	for _, tk := range []string{a1, a2} {
		if _, err := p.Consume(tk); !errors.Is(err, infrastructure.ErrInvalidTicket) {
			t.Fatalf("a revoked ticket was still accepted: %v", err)
		}
	}
	ps, err := p.Consume(b)
	if err != nil || ps.SessionID != "B" || ps.ScopeToken != "scope-B" {
		t.Fatalf("the ticket of another session: %+v, %v — it must be untouched", ps, err)
	}
}

func TestPendingSessions_RevokeSessionForASessionItDoesNotKnowIsNothing(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	tk := register(p, "A")
	if n := p.RevokeSession("never-seen"); n != 0 {
		t.Fatalf("revoked %d tickets of a session that has none", n)
	}
	if n := p.RevokeSession(""); n != 0 {
		t.Fatalf("an empty session id revoked %d tickets", n)
	}
	if _, err := p.Consume(tk); err != nil {
		t.Fatalf("an unrelated revocation took the ticket of A: %v", err)
	}
	// Twice is fine, and counts nothing the second time.
	register(p, "C")
	if p.RevokeSession("C") != 1 || p.RevokeSession("C") != 0 {
		t.Fatal("revoking C twice must count the ticket once")
	}
}

// A ticket that was already used is gone from the registry: revoking does not resurrect it
// or count it — what is open is the connection's business (the live-session registry).
func TestPendingSessions_AUsedTicketIsNotCounted(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	tk := register(p, "A")
	if _, err := p.Consume(tk); err != nil {
		t.Fatal(err)
	}
	if n := p.RevokeSession("A"); n != 0 {
		t.Fatalf("counted %d tickets for a session whose only ticket was used", n)
	}
}

// The registry is shared by the handlers that issue tickets, the connections that take them and
// the revocation that drops them: run together, none of them may race or lose a ticket.
func TestPendingSessions_RevokeSessionIsSafeBesideRegisterAndConsume(t *testing.T) {
	p := infrastructure.NewPendingSessions()
	var wg sync.WaitGroup
	for w := 0; w < 8; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 300; i++ {
				tk := register(p, "S")
				if i%3 == 0 {
					_, _ = p.Consume(tk)
				}
				if i%5 == 0 {
					p.RevokeSession("S")
				}
			}
		}(w)
	}
	wg.Wait()
	p.RevokeSession("S")
	if n := p.RevokeSession("S"); n != 0 {
		t.Fatalf("%d ticket(s) left after the last revocation", n)
	}
}

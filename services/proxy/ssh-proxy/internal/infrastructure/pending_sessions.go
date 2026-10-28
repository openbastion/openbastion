// Package infrastructure holds the SSH Proxy's outbound HTTP clients (to
// VaultCredentialIssuance and AuditIngestion) and the PendingSessions
// registry.
package infrastructure

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// PendingSession is what EstablishSession (proto/proxy/v1/proxy_control.proto,
// doc 07 §4) stashes for a session the Broker has authorized but whose
// client has not connected yet.
type PendingSession struct {
	SessionID  string
	TargetHost string
	TargetUser string
	ScopeToken string
	ExpiresAt  time.Time

	// BreakGlass is the Session Broker's authorisation for a recording waiver
	// (ADR-0009). The proxy honours it only if it was itself configured to.
	BreakGlass bool
}

// PendingSessions maps a single-use connection ticket to the session it
// authorizes. Consume removes the entry atomically with the lookup, so a
// ticket cannot be redeemed twice — mirroring the Vault's own scope-token
// single-use guarantee (ADR-0003) at the proxy's own boundary.
type PendingSessions struct {
	mu    sync.Mutex
	byTix map[string]*PendingSession
}

func NewPendingSessions() *PendingSessions {
	return &PendingSessions{byTix: map[string]*PendingSession{}}
}

// Register creates a new single-use ticket for ps and returns it. This is
// what EstablishSession's HTTP handler calls.
func (p *PendingSessions) Register(ps *PendingSession) (ticket string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ticket = randomTicket()
	p.byTix[ticket] = ps
	return ticket
}

// RevokeSession discards every ticket not yet used for sessionID and says how
// many (ADR-0018). A ticket is the only way to open a connection; one that is gone
// opens nothing, and the Vault scope token it carried is dropped with it.
func (p *PendingSessions) RevokeSession(sessionID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for ticket, ps := range p.byTix {
		if ps.SessionID == sessionID {
			delete(p.byTix, ticket)
			n++
		}
	}
	return n
}

var ErrInvalidTicket = errors.New("connection ticket unknown, expired, or already used")

// Consume looks up and removes ticket in one step. A client SSH
// connection's PasswordCallback calls this with the presented password.
func (p *PendingSessions) Consume(ticket string) (*PendingSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	ps, ok := p.byTix[ticket]
	if !ok {
		return nil, ErrInvalidTicket
	}
	delete(p.byTix, ticket)
	if time.Now().UTC().After(ps.ExpiresAt) {
		return nil, ErrInvalidTicket
	}
	return ps, nil
}

func randomTicket() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return "ticket_" + hex.EncodeToString(b)
}

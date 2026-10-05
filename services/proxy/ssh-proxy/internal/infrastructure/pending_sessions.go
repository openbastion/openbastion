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

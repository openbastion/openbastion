package infrastructure

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

var ErrInvalidScreenTicket = errors.New("rdp-vnc-proxy: connection ticket is unknown, expired, or already used")

type PendingScreenSession struct {
	SessionID  string
	ScopeToken string
	Protocol   screenstream.Protocol
	ExpiresAt  time.Time
}

// PendingScreenSessions stores only one-use admission tickets, never credentials.
type PendingScreenSessions struct {
	mu       sync.Mutex
	byTicket map[string]PendingScreenSession
}

func NewPendingScreenSessions() *PendingScreenSessions {
	return &PendingScreenSessions{byTicket: make(map[string]PendingScreenSession)}
}

func (p *PendingScreenSessions) Register(session PendingScreenSession) (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	ticket := "screen_" + hex.EncodeToString(b)
	p.mu.Lock()
	p.byTicket[ticket] = session
	p.mu.Unlock()
	return ticket, nil
}

func (p *PendingScreenSessions) Consume(ticket string, now time.Time) (PendingScreenSession, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	session, ok := p.byTicket[ticket]
	if !ok {
		return PendingScreenSession{}, ErrInvalidScreenTicket
	}
	delete(p.byTicket, ticket)
	if ticket == "" || !now.Before(session.ExpiresAt) {
		return PendingScreenSession{}, ErrInvalidScreenTicket
	}
	return session, nil
}

func (p *PendingScreenSessions) RevokeSession(sessionID string) int {
	p.mu.Lock()
	defer p.mu.Unlock()
	n := 0
	for ticket, session := range p.byTicket {
		if session.SessionID == sessionID {
			delete(p.byTicket, ticket)
			n++
		}
	}
	return n
}

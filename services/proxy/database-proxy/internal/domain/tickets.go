package domain

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sync"
	"time"
)

var (
	ErrInvalidTicket         = errors.New("connection ticket unknown, expired, or already used")
	ErrTicketCapacity        = errors.New("database proxy ticket capacity reached")
	ErrInvalidTicketCapacity = errors.New("invalid database proxy ticket capacity")
	ErrSessionTicketExists   = errors.New("session already has a pending connection ticket")
)

const (
	TicketBytes       = 32
	MaxTicketLifetime = 7 * 24 * time.Hour
)

// PendingSession contains only control metadata and a one-use Vault scope.
// It never contains target credential material.
type PendingSession struct {
	SessionID  string
	ActorID    string
	TargetHost string
	TargetUser string
	ScopeToken []byte
	ExpiresAt  time.Time
	BreakGlass bool
}

type TicketStore struct {
	mu         sync.Mutex
	pending    map[[sha256.Size]byte]PendingSession
	bySession  map[string][sha256.Size]byte
	revoked    map[string]time.Time
	maxTickets int
	now        func() time.Time
}

func NewTicketStore(maxTickets int, now func() time.Time) (*TicketStore, error) {
	if maxTickets < 1 || maxTickets > 4096 {
		return nil, ErrInvalidTicketCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &TicketStore{
		pending:    make(map[[sha256.Size]byte]PendingSession),
		bySession:  make(map[string][sha256.Size]byte),
		revoked:    make(map[string]time.Time),
		maxTickets: maxTickets,
		now:        now,
	}, nil
}

// Register issues a high-entropy opaque ticket and stores only its SHA-256 digest.
func (s *TicketStore) Register(session PendingSession) (string, error) {
	now := s.now().UTC()
	if session.SessionID == "" || len(session.ScopeToken) == 0 || !session.ExpiresAt.After(now) || session.ExpiresAt.Sub(now) > MaxTicketLifetime {
		return "", ErrInvalidTicket
	}
	raw := make([]byte, TicketBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("generate connection ticket: %w", err)
	}
	ticket := base64.RawURLEncoding.EncodeToString(raw)
	digest := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if _, revoked := s.revoked[session.SessionID]; revoked {
		return "", ErrInvalidTicket
	}
	if _, exists := s.bySession[session.SessionID]; exists {
		return "", ErrSessionTicketExists
	}
	if len(s.pending) >= s.maxTickets {
		return "", ErrTicketCapacity
	}
	session.ScopeToken = append([]byte(nil), session.ScopeToken...)
	s.pending[digest] = session
	s.bySession[session.SessionID] = digest
	return ticket, nil
}

// Consume atomically validates and removes a ticket. Only the digest is used
// for lookup, so the bearer token is never retained after registration.
func (s *TicketStore) Consume(ticket string) (PendingSession, error) {
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(raw) != TicketBytes {
		return PendingSession{}, ErrInvalidTicket
	}
	digest := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}

	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	session, ok := s.pending[digest]
	if !ok || !session.ExpiresAt.After(now) {
		return PendingSession{}, ErrInvalidTicket
	}
	delete(s.pending, digest)
	delete(s.bySession, session.SessionID)
	if _, revoked := s.revoked[session.SessionID]; revoked {
		zero(session.ScopeToken)
		return PendingSession{}, ErrInvalidTicket
	}
	return session, nil
}

// RevokeSession drops an unused ticket and remembers the revocation until expiresAt.
func (s *TicketStore) RevokeSession(sessionID string, expiresAt time.Time) int {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	if expiresAt.After(now) {
		if max := now.Add(MaxTicketLifetime); expiresAt.After(max) {
			expiresAt = max
		}
		s.revoked[sessionID] = expiresAt.UTC()
	}
	if digest, ok := s.bySession[sessionID]; ok {
		session := s.pending[digest]
		zero(session.ScopeToken)
		delete(s.pending, digest)
		delete(s.bySession, sessionID)
		return 1
	}
	return 0
}

func (s *TicketStore) IsRevoked(sessionID string) bool {
	now := s.now().UTC()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(now)
	_, ok := s.revoked[sessionID]
	return ok
}

func (s *TicketStore) pruneLocked(now time.Time) {
	for sessionID, until := range s.revoked {
		if !until.After(now) {
			delete(s.revoked, sessionID)
		}
	}
	for digest, session := range s.pending {
		if !session.ExpiresAt.After(now) {
			zero(session.ScopeToken)
			delete(s.pending, digest)
			delete(s.bySession, session.SessionID)
		}
	}
}

func zero(p []byte) {
	for i := range p {
		p[i] = 0
	}
}

// PendingCount is a bounded operational count; it never exposes ticket digests or scope tokens.
func (s *TicketStore) PendingCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.pruneLocked(s.now().UTC())
	return len(s.pending)
}

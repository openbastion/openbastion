package proxycore

import (
	"context"
	"errors"
	"sync"
	"time"
)

// ErrSessionRevoked marks a session the Session Broker told the proxy to cut
// (ADR-0018): its open connections end, its tickets are refused and it is never
// established again. Like ErrSessionExpired it is an end, not a failure of the
// proxy; callers use errors.Is to tell the operator why the connection closed.
var ErrSessionRevoked = errors.New("session revoked")

// ErrNotRevocable is what Serve answers when the Listener has no registry of the
// connections it serves: a session the proxy could not be told to cut is not
// started. The zero value of Listener is as strict as everywhere else (ADR-0008).
var ErrNotRevocable = errors.New("proxycore: the listener has no registry of live sessions; a session that could not be cut is not started")

// LiveSessions is what a proxy knows about the connections it has open, per
// session, and about the sessions it was told to cut (ADR-0018).
//
// Two things in one structure, because they have to be decided together: a
// connection that registers while its session is being revoked must either be
// cut or refused, never slip between the two. Both are under one mutex.
//
// It is protocol-agnostic and lives with the pipeline (Listener.Serve): an RDP or
// HTTP proxy built on proxycore is revocable the same way.
//
// The memory of a revocation lasts until the session would have ended by itself
// and no longer: nothing can be established for a session after that moment, so
// the entry has nothing left to refuse. It is in memory: a proxy that restarts
// loses its connections and its tickets with it, and forgets what it was told —
// which is safe, because the Broker no longer issues tickets for a session it has
// ended.
type LiveSessions struct {
	mu      sync.Mutex
	now     func() time.Time
	next    uint64
	live    map[string]map[uint64]*LiveConn
	revoked map[string]time.Time // session id -> the time after which it is forgotten
}

// NewLiveSessions returns an empty registry.
func NewLiveSessions() *LiveSessions {
	return &LiveSessions{
		now:     time.Now,
		live:    map[string]map[uint64]*LiveConn{},
		revoked: map[string]time.Time{},
	}
}

// LiveConn is one open connection of a session, as the registry knows it.
type LiveConn struct {
	sessions *LiveSessions
	session  string
	id       uint64
	cancel   context.CancelCauseFunc
	ended    chan struct{}
	once     sync.Once
}

// Begin registers an open connection of sessionID. cancel is what Revoke calls
// to end it; it is called with ErrSessionRevoked as the cause.
//
// A session that has been revoked is refused with ErrSessionRevoked, atomically
// with the registration: this is what stops a connection whose ticket was taken
// just before the revocation arrived.
func (l *LiveSessions) Begin(sessionID string, cancel context.CancelCauseFunc) (*LiveConn, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.revokedLocked(sessionID) {
		return nil, ErrSessionRevoked
	}
	l.next++
	c := &LiveConn{sessions: l, session: sessionID, id: l.next, cancel: cancel, ended: make(chan struct{})}
	if l.live[sessionID] == nil {
		l.live[sessionID] = map[uint64]*LiveConn{}
	}
	l.live[sessionID][c.id] = c
	return c, nil
}

// RelayEnded says the connection no longer carries anything: the relay returned
// and the connection to the target is closed. It is what Revoke waits for.
func (c *LiveConn) RelayEnded() { c.once.Do(func() { close(c.ended) }) }

// End forgets the connection. It also says the relay ended, for the paths that
// never got as far as a relay.
func (c *LiveConn) End() {
	c.RelayEnded()
	l := c.sessions
	l.mu.Lock()
	defer l.mu.Unlock()
	if conns := l.live[c.session]; conns != nil {
		delete(conns, c.id)
		if len(conns) == 0 {
			delete(l.live, c.session)
		}
	}
}

// Revoked says whether sessionID was revoked and not yet forgotten.
func (l *LiveSessions) Revoked(sessionID string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.revokedLocked(sessionID)
}

// RevokedUntil says until when sessionID is remembered as revoked. It is for the log
// of a revocation and for tests; nothing decides on it.
func (l *LiveSessions) RevokedUntil(sessionID string) (time.Time, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.revokedLocked(sessionID) {
		return time.Time{}, false
	}
	return l.revoked[sessionID], true
}

func (l *LiveSessions) revokedLocked(sessionID string) bool {
	until, ok := l.revoked[sessionID]
	if !ok {
		return false
	}
	if !l.now().Before(until) {
		delete(l.revoked, sessionID)
		return false
	}
	return true
}

// Revocation is what Revoke did: the connections it signalled, which the caller
// can wait for.
type Revocation struct{ conns []*LiveConn }

// Cut is how many open connections were signalled to stop.
func (r *Revocation) Cut() int { return len(r.conns) }

// Wait waits — at most d — for the signalled connections to stop carrying anything
// and returns how many had not when it gave up.
func (r *Revocation) Wait(d time.Duration) (stillOpen int) {
	timer := time.NewTimer(d)
	defer timer.Stop()
	for _, c := range r.conns {
		select {
		case <-c.ended:
		case <-timer.C:
			for _, rest := range r.conns {
				select {
				case <-rest.ended:
				default:
					stillOpen++
				}
			}
			return stillOpen
		}
	}
	return 0
}

// Revoke remembers that sessionID is cut, until `until`, and signals every open
// connection it has to stop. From the moment it returns, a connection that tries
// to register is refused. It does not wait: Wait on the result does.
//
// It is idempotent: a second call signals the connections opened since, and
// extends the memory if `until` is later. It never shortens it.
func (l *LiveSessions) Revoke(sessionID string, until time.Time) *Revocation {
	l.mu.Lock()
	now := l.now()
	for id, t := range l.revoked { // forget what has nothing left to refuse
		if !now.Before(t) {
			delete(l.revoked, id)
		}
	}
	if until.After(l.revoked[sessionID]) {
		l.revoked[sessionID] = until
	}
	conns := make([]*LiveConn, 0, len(l.live[sessionID]))
	for _, c := range l.live[sessionID] {
		conns = append(conns, c)
	}
	l.mu.Unlock()

	for _, c := range conns {
		c.cancel(ErrSessionRevoked)
	}
	return &Revocation{conns: conns}
}

// OpenConnections is how many connections of sessionID are registered. For tests
// and for the operator's log; nothing decides on it.
func (l *LiveSessions) OpenConnections(sessionID string) int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return len(l.live[sessionID])
}

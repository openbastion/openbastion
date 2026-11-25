package domain

import (
	"errors"
	"fmt"
	"sync"
)

var (
	ErrConnectionLimit         = errors.New("database proxy connection limit reached")
	ErrInvalidConnectionLimits = errors.New("invalid database proxy connection limits")
)

const (
	DefaultMaxConnections            = 256
	DefaultMaxConnectionsPerTarget   = 32
	DefaultMaxConnectionsPerActor    = 8
	DefaultMaxConnectionsPerSession  = 1
	MaxConnectionsHardLimit          = 1024
	MaxConnectionsPerTargetHardLimit = 256
	MaxConnectionsPerActorHardLimit  = 64
)

type ConnectionLimits struct {
	MaxTotal      int
	MaxPerTarget  int
	MaxPerActor   int
	MaxPerSession int
}

func DefaultConnectionLimits() ConnectionLimits {
	return ConnectionLimits{
		MaxTotal:      DefaultMaxConnections,
		MaxPerTarget:  DefaultMaxConnectionsPerTarget,
		MaxPerActor:   DefaultMaxConnectionsPerActor,
		MaxPerSession: DefaultMaxConnectionsPerSession,
	}
}

type ConnectionLimiter struct {
	mu        sync.Mutex
	limits    ConnectionLimits
	total     int
	byTarget  map[string]int
	byActor   map[string]int
	bySession map[string]int
}

func NewConnectionLimiter(limits ConnectionLimits) (*ConnectionLimiter, error) {
	if limits.MaxTotal < 1 || limits.MaxTotal > MaxConnectionsHardLimit ||
		limits.MaxPerTarget < 1 || limits.MaxPerTarget > MaxConnectionsPerTargetHardLimit || limits.MaxPerTarget > limits.MaxTotal ||
		limits.MaxPerActor < 1 || limits.MaxPerActor > MaxConnectionsPerActorHardLimit || limits.MaxPerActor > limits.MaxTotal ||
		limits.MaxPerSession != DefaultMaxConnectionsPerSession {
		return nil, fmt.Errorf("%w: total 1..%d, target 1..%d, actor 1..%d, session exactly 1", ErrInvalidConnectionLimits,
			MaxConnectionsHardLimit, MaxConnectionsPerTargetHardLimit, MaxConnectionsPerActorHardLimit)
	}
	return &ConnectionLimiter{
		limits:    limits,
		byTarget:  make(map[string]int),
		byActor:   make(map[string]int),
		bySession: make(map[string]int),
	}, nil
}

// Acquire reserves one active database connection. The returned release is idempotent.
func (l *ConnectionLimiter) Acquire(targetID, actorID, sessionID string) (func(), error) {
	if targetID == "" || actorID == "" || sessionID == "" {
		return nil, ErrInvalidConnectionLimits
	}
	l.mu.Lock()
	if l.total >= l.limits.MaxTotal || l.byTarget[targetID] >= l.limits.MaxPerTarget ||
		l.byActor[actorID] >= l.limits.MaxPerActor || l.bySession[sessionID] >= l.limits.MaxPerSession {
		l.mu.Unlock()
		return nil, ErrConnectionLimit
	}
	l.total++
	l.byTarget[targetID]++
	l.byActor[actorID]++
	l.bySession[sessionID]++
	l.mu.Unlock()

	var once sync.Once
	return func() {
		once.Do(func() {
			l.mu.Lock()
			defer l.mu.Unlock()
			l.total--
			decrement(l.byTarget, targetID)
			decrement(l.byActor, actorID)
			decrement(l.bySession, sessionID)
		})
	}, nil
}

func (l *ConnectionLimiter) Active() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.total
}

func decrement(counts map[string]int, key string) {
	if counts[key] <= 1 {
		delete(counts, key)
		return
	}
	counts[key]--
}

package domain

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidCancelRequest   = errors.New("postgresql cancel request is unknown or not authorized")
	ErrCancelRegistryCapacity = errors.New("database proxy cancel registry capacity reached")
)

const MaxCancelRegistryEntries = 1024

type CancelKey struct {
	ProcessID uint32
	SecretKey uint32
}

type CancelTarget struct {
	SessionID  string
	TargetAddr string
	ProcessID  uint32
	SecretKey  uint32
	ExpiresAt  time.Time
}

type cancelEntry struct {
	CancelTarget
	clientIP string
}

type CancelRegistry struct {
	mu         sync.Mutex
	byKey      map[CancelKey]cancelEntry
	bySession  map[string]CancelKey
	maxEntries int
	now        func() time.Time
}

func NewCancelRegistry(maxEntries int, now func() time.Time) (*CancelRegistry, error) {
	if maxEntries < 1 || maxEntries > MaxCancelRegistryEntries {
		return nil, ErrCancelRegistryCapacity
	}
	if now == nil {
		now = time.Now
	}
	return &CancelRegistry{
		byKey:      make(map[CancelKey]cancelEntry),
		bySession:  make(map[string]CancelKey),
		maxEntries: maxEntries,
		now:        now,
	}, nil
}

// Register creates a client-visible key unrelated to the upstream PostgreSQL
// BackendKeyData and pins it to the peer IP and the already-resolved target IP.
func (r *CancelRegistry) Register(sessionID, clientIP, targetAddr string, upstreamPID, upstreamSecret uint32, expiresAt time.Time) (CancelKey, error) {
	client := net.ParseIP(strings.TrimSpace(clientIP))
	targetHost, targetPort, err := net.SplitHostPort(targetAddr)
	if sessionID == "" || client == nil || net.ParseIP(targetHost) == nil || err != nil || upstreamPID == 0 || upstreamSecret == 0 {
		return CancelKey{}, ErrInvalidCancelRequest
	}
	port, err := strconv.Atoi(targetPort)
	if err != nil || port < 1 || port > 65535 {
		return CancelKey{}, ErrInvalidCancelRequest
	}
	now := r.now().UTC()
	if !expiresAt.After(now) || expiresAt.Sub(now) > MaxTicketLifetime {
		return CancelKey{}, ErrInvalidCancelRequest
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	if _, exists := r.bySession[sessionID]; exists {
		return CancelKey{}, ErrInvalidCancelRequest
	}
	if len(r.byKey) >= r.maxEntries {
		return CancelKey{}, ErrCancelRegistryCapacity
	}
	for attempts := 0; attempts < 8; attempts++ {
		var raw [8]byte
		if _, err := rand.Read(raw[:]); err != nil {
			return CancelKey{}, fmt.Errorf("generate frontend cancel key: %w", err)
		}
		key := CancelKey{ProcessID: binary.BigEndian.Uint32(raw[:4]), SecretKey: binary.BigEndian.Uint32(raw[4:])}
		if key.ProcessID == 0 || key.SecretKey == 0 || key.ProcessID == upstreamPID && key.SecretKey == upstreamSecret {
			continue
		}
		if _, collision := r.byKey[key]; collision {
			continue
		}
		entry := cancelEntry{CancelTarget: CancelTarget{
			SessionID: sessionID, TargetAddr: net.JoinHostPort(net.ParseIP(targetHost).String(), strconv.Itoa(port)),
			ProcessID: upstreamPID, SecretKey: upstreamSecret, ExpiresAt: expiresAt.UTC(),
		}, clientIP: client.String()}
		r.byKey[key] = entry
		r.bySession[sessionID] = key
		return key, nil
	}
	return CancelKey{}, ErrInvalidCancelRequest
}

// Resolve returns the upstream cancellation tuple only for the same client IP.
func (r *CancelRegistry) Resolve(key CancelKey, clientIP string) (CancelTarget, error) {
	client := net.ParseIP(strings.TrimSpace(clientIP))
	if client == nil {
		return CancelTarget{}, ErrInvalidCancelRequest
	}
	now := r.now().UTC()
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	entry, ok := r.byKey[key]
	if !ok || entry.clientIP != client.String() || !entry.ExpiresAt.After(now) {
		return CancelTarget{}, ErrInvalidCancelRequest
	}
	return entry.CancelTarget, nil
}

func (r *CancelRegistry) RemoveSession(sessionID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if key, ok := r.bySession[sessionID]; ok {
		delete(r.byKey, key)
		delete(r.bySession, sessionID)
	}
}

func (r *CancelRegistry) pruneLocked(now time.Time) {
	for key, entry := range r.byKey {
		if !entry.ExpiresAt.After(now) {
			delete(r.byKey, key)
			delete(r.bySession, entry.SessionID)
		}
	}
}

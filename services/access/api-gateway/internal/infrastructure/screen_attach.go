package infrastructure

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/mtls"
)

var ErrScreenAttachInvalid = errors.New("screen attach is unknown, expired, or already used")

type ScreenAttach struct {
	SessionID string
	UserID    string
	Endpoint  string
	Ticket    string
	ExpiresAt time.Time
}

type upgradeWindow struct {
	startedAt time.Time
	count     int
}

type ScreenAttachRegistry struct {
	mu             sync.Mutex
	entries        map[string]ScreenAttach
	activeSessions map[string]string
	upgrades       map[string]upgradeWindow
}

func NewScreenAttachRegistry() *ScreenAttachRegistry {
	return &ScreenAttachRegistry{entries: make(map[string]ScreenAttach), activeSessions: make(map[string]string), upgrades: make(map[string]upgradeWindow)}
}
func (r *ScreenAttachRegistry) Register(a ScreenAttach) (string, error) {
	if a.SessionID == "" || a.UserID == "" || a.Endpoint == "" || a.Ticket == "" || a.ExpiresAt.IsZero() {
		return "", ErrScreenAttachInvalid
	}
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("screen attach token generation failed")
	}
	token := hex.EncodeToString(b)
	r.mu.Lock()
	now := time.Now()
	r.pruneLocked(now)
	if _, active := r.activeSessions[a.SessionID]; active {
		r.mu.Unlock()
		return "", ErrScreenAttachInvalid
	}
	for key, entry := range r.entries {
		if entry.SessionID == a.SessionID {
			delete(r.entries, key)
		}
	}
	r.entries[token] = a
	r.mu.Unlock()
	return token, nil
}
func (r *ScreenAttachRegistry) Consume(token, sessionID string, now time.Time) (ScreenAttach, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	a, ok := r.entries[token]
	if !ok || token == "" {
		return ScreenAttach{}, ErrScreenAttachInvalid
	}
	// A token presented on another session path is not consumed: otherwise a
	// caller who learned one cookie could invalidate it by guessing another ID.
	if a.SessionID != sessionID {
		return ScreenAttach{}, ErrScreenAttachInvalid
	}
	if !now.Before(a.ExpiresAt) {
		delete(r.entries, token)
		return ScreenAttach{}, ErrScreenAttachInvalid
	}
	if _, active := r.activeSessions[sessionID]; active {
		delete(r.entries, token)
		return ScreenAttach{}, ErrScreenAttachInvalid
	}
	delete(r.entries, token)
	r.activeSessions[sessionID] = a.UserID
	return a, nil
}

// AllowUpgrade bounds successful screen WebSocket upgrades to ten per user per minute.
func (r *ScreenAttachRegistry) AllowUpgrade(userID string, now time.Time) bool {
	if userID == "" {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pruneLocked(now)
	w := r.upgrades[userID]
	if w.startedAt.IsZero() || now.Before(w.startedAt) || now.Sub(w.startedAt) >= time.Minute {
		w = upgradeWindow{startedAt: now}
	}
	if w.count >= 10 {
		r.upgrades[userID] = w
		return false
	}
	w.count++
	r.upgrades[userID] = w
	return true
}

func (r *ScreenAttachRegistry) ReleaseSession(sessionID string) {
	r.mu.Lock()
	delete(r.activeSessions, sessionID)
	r.mu.Unlock()
}

func (r *ScreenAttachRegistry) pruneLocked(now time.Time) {
	for token, entry := range r.entries {
		if !now.Before(entry.ExpiresAt) {
			delete(r.entries, token)
		}
	}
	for user, window := range r.upgrades {
		if now.Before(window.startedAt) || now.Sub(window.startedAt) >= time.Minute {
			delete(r.upgrades, user)
		}
	}
}

type ScreenWebSocketDialer struct{ Runtime *mtls.Runtime }

func (d *ScreenWebSocketDialer) Dial(ctx context.Context, endpoint, ticket string) (*websocket.Conn, error) {
	if d == nil || d.Runtime == nil || ticket == "" {
		return nil, ErrScreenAttachInvalid
	}
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil || host == "" || strings.ContainsAny(endpoint, "/?#@") {
		return nil, ErrScreenAttachInvalid
	}
	scheme := "https"
	if !d.Runtime.Enabled() {
		scheme = "http"
	}
	base := scheme + "://" + endpoint
	u, err := url.Parse(base)
	if err != nil || u.Host != endpoint {
		return nil, ErrScreenAttachInvalid
	}
	client, err := d.Runtime.Client(mtls.Peer{URL: base, Service: mtls.RDPVNCProxy})
	if err != nil {
		return nil, err
	}
	headers := http.Header{}
	headers.Set("Authorization", "Bearer "+ticket)
	conn, _, err := websocket.Dial(ctx, base+"/internal/v1/screen", &websocket.DialOptions{HTTPClient: client, HTTPHeader: headers, Subprotocols: []string{"openbastion.screen.v1"}})
	if err != nil {
		return nil, fmt.Errorf("screen proxy attach failed")
	}
	conn.SetReadLimit((4 << 20) + 4096)
	return conn, nil
}

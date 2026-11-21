package infrastructure

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

var (
	ErrSecretSessionInactive  = errors.New("secret input session is not active")
	ErrSecretSessionAmbiguous = errors.New("secret input session has multiple active screen streams")
)

type screenSecretInputSession struct {
	ctx        context.Context
	protocol   string
	targetHost string
	targetUser string
	typer      proxycore.SecretTyper
	recorder   proxycore.SecretInputRecorder
}

// SecretInputRegistry contains only live VNC/RDP input handles. Entries are
// removed with the screen relay and never contain credential bytes or scopes.
type SecretInputRegistry struct {
	mu       sync.RWMutex
	sessions map[string]map[*screenSecretInputSession]struct{}

	// The paste tokens the Session Broker issued after the operator's second factor (ADR-0133 §2):
	// one per paste, for one session, until it expires. Auditor audits a paste, as a Vault secret.
	pasteMu sync.Mutex
	pastes  map[[screenstream.PasteTokenSize]byte]pasteGrant
	Auditor proxycore.SecretInputAuditor
	now     func() time.Time
}

type pasteGrant struct {
	sessionID, accountID string
	expires              time.Time
}

// MaxPasteTTL bounds how long a paste token lives; maxPasteGrants how many wait at once.
const (
	MaxPasteTTL    = 60 * time.Second
	maxPasteGrants = 1024
)

var ErrPasteGrantInvalid = errors.New("invalid paste grant")

func NewSecretInputRegistry() *SecretInputRegistry {
	return &SecretInputRegistry{sessions: make(map[string]map[*screenSecretInputSession]struct{}),
		pastes: make(map[[screenstream.PasteTokenSize]byte]pasteGrant), now: time.Now}
}

// AuthorizePaste keeps a paste token for a live screen session, until ttl (at most MaxPasteTTL).
func (r *SecretInputRegistry) AuthorizePaste(sessionID, accountID string, token [screenstream.PasteTokenSize]byte, ttl time.Duration) error {
	if r == nil || !safeInjectionIdentifier(sessionID, 256) || !safeInjectionIdentifier(accountID, 128) ||
		ttl <= 0 || ttl > MaxPasteTTL || token == ([screenstream.PasteTokenSize]byte{}) {
		return ErrPasteGrantInvalid
	}
	r.mu.RLock()
	live := len(r.sessions[sessionID]) == 1
	r.mu.RUnlock()
	if !live {
		return ErrSecretSessionInactive
	}
	r.pasteMu.Lock()
	defer r.pasteMu.Unlock()
	now := r.now()
	for t, g := range r.pastes { // expired grants go first
		if !now.Before(g.expires) {
			delete(r.pastes, t)
		}
	}
	if _, taken := r.pastes[token]; taken || len(r.pastes) >= maxPasteGrants {
		return ErrPasteGrantInvalid
	}
	r.pastes[token] = pasteGrant{sessionID: sessionID, accountID: accountID, expires: now.Add(ttl)}
	return nil
}

// TakePaste consumes a paste token for this session: once, before it expires.
func (r *SecretInputRegistry) TakePaste(sessionID string, token [screenstream.PasteTokenSize]byte) (string, bool) {
	if r == nil {
		return "", false
	}
	r.pasteMu.Lock()
	defer r.pasteMu.Unlock()
	grant, ok := r.pastes[token]
	if !ok {
		return "", false
	}
	delete(r.pastes, token) // taken, whatever comes next
	if grant.sessionID != sessionID || !r.now().Before(grant.expires) {
		return "", false
	}
	return grant.accountID, true
}

// PasteAuditor is the auditor of the pastes (proxycore.PasteAuditing).
func (r *SecretInputRegistry) PasteAuditor() proxycore.SecretInputAuditor {
	if r == nil {
		return nil
	}
	return r.Auditor
}

func (r *SecretInputRegistry) Register(ctx context.Context, sessionID, protocol, targetHost, targetUser string, typer proxycore.SecretTyper, recorder proxycore.SecretInputRecorder) func() {
	if r == nil || ctx == nil || ctx.Err() != nil || sessionID == "" ||
		(protocol != "vnc" && protocol != "rdp") || targetHost == "" || targetUser == "" || typer == nil || recorder == nil {
		return func() {}
	}
	entry := &screenSecretInputSession{ctx: ctx, protocol: protocol, targetHost: targetHost, targetUser: targetUser, typer: typer, recorder: recorder}
	r.mu.Lock()
	entries := r.sessions[sessionID]
	if entries == nil {
		entries = make(map[*screenSecretInputSession]struct{})
		r.sessions[sessionID] = entries
	}
	entries[entry] = struct{}{}
	r.mu.Unlock()
	return func() {
		r.mu.Lock()
		if current := r.sessions[sessionID]; current != nil {
			delete(current, entry)
			if len(current) == 0 {
				delete(r.sessions, sessionID)
			}
		}
		r.mu.Unlock()
	}
}

// InjectVaultScope checks the live screen session before consuming the one-use
// Vault scope. The registry read lock serializes injection with relay cleanup.
func (r *SecretInputRegistry) InjectVaultScope(ctx context.Context, sessionID, accountID, scopeToken string, fetcher *proxycore.CredentialFetcher, auditor proxycore.SecretInputAuditor) error {
	if r == nil || ctx == nil || fetcher == nil || auditor == nil ||
		!safeInjectionIdentifier(sessionID, 256) || !safeInjectionIdentifier(accountID, 128) || !safeInjectionScope(scopeToken) {
		return proxycore.ErrSecretInjectionInvalid
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	entries := r.sessions[sessionID]
	if len(entries) == 0 {
		return ErrSecretSessionInactive
	}
	if len(entries) != 1 {
		return ErrSecretSessionAmbiguous
	}
	var entry *screenSecretInputSession
	for active := range entries {
		entry = active
	}
	if err := entry.ctx.Err(); err != nil {
		return ErrSecretSessionInactive
	}
	injectCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(entry.ctx, cancel)
	defer func() { stop(); cancel() }()
	if err := injectCtx.Err(); err != nil {
		return err
	}
	credential, err := fetcher.Fetch(injectCtx, scopeToken)
	if err != nil {
		return err
	}
	defer credential.Purge()
	if credential.Type != "password" || credential.TargetHost != entry.targetHost || credential.TargetUser != entry.targetUser {
		return proxycore.ErrSecretInjectionInvalid
	}
	return proxycore.InjectSecret(injectCtx, sessionID, entry.protocol, proxycore.SecretInputVault, accountID,
		credential.Material(), auditor, entry.recorder, entry.typer)
}

func safeInjectionIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

func safeInjectionScope(value string) bool {
	if value == "" || len(value) > 8192 {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.') {
			return false
		}
	}
	return true
}

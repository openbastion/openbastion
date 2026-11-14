package infrastructure

import (
	"context"
	"errors"
	"sync"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

var (
	ErrSecretSessionInactive  = errors.New("secret input session is not active")
	ErrSecretSessionAmbiguous = errors.New("secret input session has multiple active shells")
)

type secretInputSession struct {
	ctx        context.Context
	protocol   string
	targetHost string
	targetUser string
	typer      proxycore.SecretTyper
	recorder   proxycore.SecretInputRecorder
}

// SecretInputRegistry contains only live protocol input handles. Registrations
// exist for the lifetime of the interactive target shell and are removed when
// the relay exits. It never stores credential bytes.
type SecretInputRegistry struct {
	mu       sync.RWMutex
	sessions map[string]map[*secretInputSession]struct{}
}

func NewSecretInputRegistry() *SecretInputRegistry {
	return &SecretInputRegistry{sessions: make(map[string]map[*secretInputSession]struct{})}
}

func (r *SecretInputRegistry) Register(ctx context.Context, sessionID, protocol, targetHost, targetUser string, typer proxycore.SecretTyper, recorder proxycore.SecretInputRecorder) func() {
	if r == nil || ctx == nil || ctx.Err() != nil || sessionID == "" || protocol != "ssh" || targetHost == "" || targetUser == "" || typer == nil || recorder == nil {
		return func() {}
	}
	entry := &secretInputSession{ctx: ctx, protocol: protocol, targetHost: targetHost, targetUser: targetUser, typer: typer, recorder: recorder}
	r.mu.Lock()
	entries := r.sessions[sessionID]
	if entries == nil {
		entries = make(map[*secretInputSession]struct{})
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

// InjectVaultScope checks the live session before consuming the one-use Vault
// scope. The read lock is held through fetch and typing so relay cleanup cannot
// unregister the target input stream midway through the operation.
func (r *SecretInputRegistry) InjectVaultScope(ctx context.Context, sessionID, accountID, scopeToken string, fetcher *proxycore.CredentialFetcher, auditor proxycore.SecretInputAuditor) error {
	if r == nil || ctx == nil || fetcher == nil || auditor == nil || scopeToken == "" {
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
	var entry *secretInputSession
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

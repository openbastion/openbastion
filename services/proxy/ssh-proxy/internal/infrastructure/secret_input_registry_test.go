package infrastructure_test

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
)

type secretVault struct {
	mu      sync.Mutex
	calls   int
	fetched proxycore.Fetched
	err     error
}

func (v *secretVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	if v.err != nil {
		return proxycore.Fetched{}, v.err
	}
	return v.fetched, nil
}

type secretTyper struct {
	mu    sync.Mutex
	input []byte
}

func (t *secretTyper) WithExclusiveInput(ctx context.Context, fn func() error) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn()
}
func (t *secretTyper) TypeSecret(ctx context.Context, b []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.input = append([]byte(nil), b...)
	return nil
}

type secretRecorder struct {
	calls    int
	evidence proxycore.SecretInputEvidence
}

func (r *secretRecorder) RecordSecretInput(_ context.Context, e proxycore.SecretInputEvidence) error {
	r.calls++
	r.evidence = e
	return nil
}

type secretAuditor struct {
	calls    int
	evidence proxycore.SecretInputEvidence
	err      error
}

func (a *secretAuditor) AuditSecretInput(_ context.Context, e proxycore.SecretInputEvidence) error {
	a.calls++
	a.evidence = e
	return a.err
}
func (a *secretAuditor) AuditSecretInputResult(_ context.Context, _ proxycore.SecretInputEvidence, _ bool) error {
	a.calls++
	return a.err
}

func TestSecretInputRegistry_FetchesFromVaultAndTypesOnlyIntoLiveTarget(t *testing.T) {
	material := []byte("vault-password")
	vault := &secretVault{fetched: proxycore.Fetched{Type: "password", Material: material, TargetHost: "10.0.0.5:22", TargetUser: "root"}}
	fetcher := proxycore.NewCredentialFetcher(vault, "ssh-proxy")
	registry := infrastructure.NewSecretInputRegistry()
	typer := &secretTyper{}
	recorder := &secretRecorder{}
	cleanup := registry.Register(context.Background(), "session-1", "ssh", "10.0.0.5:22", "root", typer, recorder)
	defer cleanup()
	auditor := &secretAuditor{}

	if err := registry.InjectVaultScope(context.Background(), "session-1", "account-1", "one-use-scope", fetcher, auditor); err != nil {
		t.Fatal(err)
	}
	if string(typer.input) != "vault-password" {
		t.Fatalf("typed %q", typer.input)
	}
	if auditor.calls != 2 || recorder.calls != 1 {
		t.Fatalf("audit=%d record=%d", auditor.calls, recorder.calls)
	}
	if auditor.evidence.AccountID != "account-1" || recorder.evidence.SessionID != "session-1" {
		t.Fatalf("unsafe evidence: %+v %+v", auditor.evidence, recorder.evidence)
	}
	for i, b := range material {
		if b != 0 {
			t.Fatalf("vault material byte %d not purged", i)
		}
	}
}

func TestSecretInputRegistry_DoesNotConsumeScopeWhenSessionIsNotLive(t *testing.T) {
	vault := &secretVault{fetched: proxycore.Fetched{Type: "password", Material: []byte("secret"), TargetHost: "host:22", TargetUser: "root"}}
	registry := infrastructure.NewSecretInputRegistry()
	err := registry.InjectVaultScope(context.Background(), "not-live", "account", "scope", proxycore.NewCredentialFetcher(vault, "ssh-proxy"), &secretAuditor{})
	if !errors.Is(err, infrastructure.ErrSecretSessionInactive) {
		t.Fatalf("err=%v", err)
	}
	if vault.calls != 0 {
		t.Fatalf("Vault scope fetched for inactive session: calls=%d", vault.calls)
	}
}

func TestSecretInputRegistry_RejectsCredentialForDifferentTargetAndPurges(t *testing.T) {
	material := []byte("wrong-target-secret")
	vault := &secretVault{fetched: proxycore.Fetched{Type: "password", Material: material, TargetHost: "other:22", TargetUser: "root"}}
	registry := infrastructure.NewSecretInputRegistry()
	cleanup := registry.Register(context.Background(), "session-1", "ssh", "10.0.0.5:22", "root", &secretTyper{}, &secretRecorder{})
	defer cleanup()
	err := registry.InjectVaultScope(context.Background(), "session-1", "account", "scope", proxycore.NewCredentialFetcher(vault, "ssh-proxy"), &secretAuditor{})
	if !errors.Is(err, proxycore.ErrSecretInjectionInvalid) {
		t.Fatalf("err=%v", err)
	}
	for i, b := range material {
		if b != 0 {
			t.Fatalf("credential byte %d not purged", i)
		}
	}
}

func TestSecretInputRegistry_RefusesAmbiguousSessionWithMultipleShells(t *testing.T) {
	vault := &secretVault{fetched: proxycore.Fetched{Type: "password", Material: []byte("secret"), TargetHost: "host:22", TargetUser: "root"}}
	registry := infrastructure.NewSecretInputRegistry()
	ctx := context.Background()
	firstCleanup := registry.Register(ctx, "session-1", "ssh", "host:22", "root", &secretTyper{}, &secretRecorder{})
	secondTyper := &secretTyper{}
	secondCleanup := registry.Register(ctx, "session-1", "ssh", "host:22", "root", secondTyper, &secretRecorder{})
	defer secondCleanup()
	err := registry.InjectVaultScope(ctx, "session-1", "account", "scope", proxycore.NewCredentialFetcher(vault, "ssh-proxy"), &secretAuditor{})
	if !errors.Is(err, infrastructure.ErrSecretSessionAmbiguous) {
		t.Fatalf("err=%v", err)
	}
	if vault.calls != 0 {
		t.Fatalf("Vault called for ambiguous session: %d", vault.calls)
	}
	firstCleanup()
	err = registry.InjectVaultScope(ctx, "session-1", "account", "scope", proxycore.NewCredentialFetcher(vault, "ssh-proxy"), &secretAuditor{})
	if err != nil {
		t.Fatalf("remaining live shell should be selected: %v", err)
	}
	if string(secondTyper.input) != "secret" {
		t.Fatalf("remaining shell received %q", secondTyper.input)
	}
}

func TestSecretInputRegistry_DoesNotFetchAfterSessionContextIsCanceled(t *testing.T) {
	vault := &secretVault{fetched: proxycore.Fetched{Type: "password", Material: []byte("secret"), TargetHost: "host:22", TargetUser: "root"}}
	registry := infrastructure.NewSecretInputRegistry()
	sessionCtx, cancel := context.WithCancel(context.Background())
	registry.Register(sessionCtx, "session-1", "ssh", "host:22", "root", &secretTyper{}, &secretRecorder{})
	cancel()
	err := registry.InjectVaultScope(context.Background(), "session-1", "account", "scope", proxycore.NewCredentialFetcher(vault, "ssh-proxy"), &secretAuditor{})
	if !errors.Is(err, infrastructure.ErrSecretSessionInactive) {
		t.Fatalf("err=%v", err)
	}
	if vault.calls != 0 {
		t.Fatalf("Vault called after session cancellation: %d", vault.calls)
	}
}

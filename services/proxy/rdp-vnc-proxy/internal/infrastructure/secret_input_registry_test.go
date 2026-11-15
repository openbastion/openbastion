package infrastructure_test

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
)

type injectionVault struct {
	mu      sync.Mutex
	calls   int
	fetched proxycore.Fetched
}

func (v *injectionVault) FetchCredential(_ context.Context, _, _ string) (proxycore.Fetched, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.calls++
	return v.fetched, nil
}

type injectionEvidence struct {
	mu    sync.Mutex
	order []string
	start proxycore.SecretInputEvidence
	end   bool
}

func (e *injectionEvidence) add(value string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.order = append(e.order, value)
}
func (e *injectionEvidence) AuditSecretInput(_ context.Context, evidence proxycore.SecretInputEvidence) error {
	e.start = evidence
	e.add("audit-start")
	return nil
}
func (e *injectionEvidence) AuditSecretInputResult(_ context.Context, _ proxycore.SecretInputEvidence, success bool) error {
	e.end = success
	e.add("audit-result")
	return nil
}
func (e *injectionEvidence) RecordSecretInput(_ context.Context, evidence proxycore.SecretInputEvidence) error {
	if evidence.Source != proxycore.SecretInputVault || evidence.Length != 0 || evidence.SHA256 != "" {
		return errors.New("unsafe evidence")
	}
	e.add("record")
	return nil
}

type injectionTyper struct {
	evidence *injectionEvidence
	secret   []byte
}

func (t *injectionTyper) WithExclusiveInput(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}
func (t *injectionTyper) TypeSecret(ctx context.Context, secret []byte) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	t.secret = append([]byte(nil), secret...)
	t.evidence.add("type")
	return nil
}

func TestSecretInputRegistryInjectsOnlyIntoLiveMatchingScreenSession(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	evidence := &injectionEvidence{}
	typer := &injectionTyper{evidence: evidence}
	registry := infrastructure.NewSecretInputRegistry()
	unregister := registry.Register(ctx, "session-1", "vnc", "vnc.example:5900", "operator", typer, evidence)
	defer unregister()
	vault := &injectionVault{fetched: proxycore.Fetched{Type: "password", Material: []byte("vault-secret"), TargetHost: "vnc.example:5900", TargetUser: "operator"}}
	fetcher := proxycore.NewCredentialFetcher(vault, "rdp-vnc-proxy")
	if err := registry.InjectVaultScope(context.Background(), "session-1", "account-prod", "one-use-scope", fetcher, evidence); err != nil {
		t.Fatalf("InjectVaultScope: %v", err)
	}
	if string(typer.secret) != "vault-secret" {
		t.Fatalf("typed bytes = %q", typer.secret)
	}
	if !reflect.DeepEqual(evidence.order, []string{"audit-start", "record", "type", "audit-result"}) {
		t.Fatalf("ordering = %#v", evidence.order)
	}
	if evidence.start.SessionID != "session-1" || evidence.start.Protocol != "vnc" || evidence.start.AccountID != "account-prod" || evidence.start.Source != proxycore.SecretInputVault || evidence.start.Length != 0 || evidence.start.SHA256 != "" || !evidence.end {
		t.Fatalf("unsafe or incomplete evidence: %#v", evidence.start)
	}
	vault.mu.Lock()
	calls := vault.calls
	vault.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Vault fetch calls = %d", calls)
	}
}

type revocationBlockingScreenTyper struct {
	started chan struct{}
}

func (t *revocationBlockingScreenTyper) WithExclusiveInput(ctx context.Context, operation func() error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	return operation()
}

func (t *revocationBlockingScreenTyper) TypeSecret(ctx context.Context, _ []byte) error {
	close(t.started)
	<-ctx.Done()
	return ctx.Err()
}

func TestSecretInputRegistry_CancelsInFlightInjectionWhenScreenSessionIsRevoked(t *testing.T) {
	material := []byte("must-not-be-typed-after-revocation")
	vault := &injectionVault{fetched: proxycore.Fetched{Type: "password", Material: material, TargetHost: "rdp.example:3389", TargetUser: "operator"}}
	registry := infrastructure.NewSecretInputRegistry()
	live := proxycore.NewLiveSessions()
	sessionCtx, revokeSession := context.WithCancelCause(context.Background())
	liveConn, err := live.Begin("session-1", revokeSession)
	if err != nil {
		t.Fatal(err)
	}
	typer := &revocationBlockingScreenTyper{started: make(chan struct{})}
	registry.Register(sessionCtx, "session-1", "rdp", "rdp.example:3389", "operator", typer, &injectionEvidence{})
	result := make(chan error, 1)
	go func() {
		result <- registry.InjectVaultScope(context.Background(), "session-1", "account", "scope",
			proxycore.NewCredentialFetcher(vault, "rdp-vnc-proxy"), &injectionEvidence{})
	}()
	select {
	case <-typer.started:
	case <-time.After(2 * time.Second):
		t.Fatal("injection did not reach the screen input operation")
	}
	// Use the same LiveSessions.Revoke operation as the proxy's internal route.
	revocation := live.Revoke("session-1", time.Now().Add(time.Minute))
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("in-flight screen injection succeeded after session revocation")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("in-flight screen injection did not stop after session revocation")
	}
	liveConn.RelayEnded()
	if stillOpen := revocation.Wait(time.Second); stillOpen != 0 {
		t.Fatalf("revocation still sees %d open relay(s) after injection stopped", stillOpen)
	}
	liveConn.End()
	for i, b := range material {
		if b != 0 {
			t.Fatalf("Vault material byte %d was not purged after revocation", i)
		}
	}
}

func TestSecretInputRegistryRefusesInactiveAmbiguousAndWrongTarget(t *testing.T) {
	vault := &injectionVault{fetched: proxycore.Fetched{Type: "password", Material: []byte("secret"), TargetHost: "other.example:5900", TargetUser: "operator"}}
	fetcher := proxycore.NewCredentialFetcher(vault, "rdp-vnc-proxy")
	evidence := &injectionEvidence{}
	typer := &injectionTyper{evidence: evidence}
	registry := infrastructure.NewSecretInputRegistry()
	if err := registry.InjectVaultScope(context.Background(), "missing", "account", "scope", fetcher, evidence); !errors.Is(err, infrastructure.ErrSecretSessionInactive) {
		t.Fatalf("inactive session error = %v", err)
	}
	if err := registry.InjectVaultScope(context.Background(), "missing", "invalid account", "scope", fetcher, evidence); !errors.Is(err, proxycore.ErrSecretInjectionInvalid) {
		t.Fatalf("invalid account error = %v", err)
	}
	ctx := context.Background()
	stop := registry.Register(ctx, "session-2", "rdp", "rdp.example:3389", "operator", typer, evidence)
	defer stop()
	stopSecond := registry.Register(ctx, "session-2", "rdp", "rdp.example:3389", "operator", typer, evidence)
	defer stopSecond()
	if err := registry.InjectVaultScope(context.Background(), "session-2", "account", "scope", fetcher, evidence); !errors.Is(err, infrastructure.ErrSecretSessionAmbiguous) {
		t.Fatalf("ambiguous session error = %v", err)
	}
	stopSecond()
	if err := registry.InjectVaultScope(context.Background(), "session-2", "account", "scope", fetcher, evidence); !errors.Is(err, proxycore.ErrSecretInjectionInvalid) {
		t.Fatalf("wrong target error = %v", err)
	}
	vault.mu.Lock()
	calls := vault.calls
	vault.mu.Unlock()
	if calls != 1 {
		t.Fatalf("Vault fetch calls = %d, want only wrong-target fetch", calls)
	}
}

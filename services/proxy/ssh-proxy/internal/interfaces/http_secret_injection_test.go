package interfaces_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

type injectionVault struct {
	calls    int
	material []byte
}

func (v *injectionVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	v.calls++
	return proxycore.Fetched{Type: "password", Material: v.material, TargetHost: "10.0.0.5:22", TargetUser: "root"}, nil
}

type injectionTyper struct{ got []byte }

func (t *injectionTyper) WithExclusiveInput(ctx context.Context, fn func() error) error { return fn() }
func (t *injectionTyper) TypeSecret(_ context.Context, b []byte) error {
	t.got = append([]byte(nil), b...)
	return nil
}

type injectionRecorder struct{ calls int }

func (r *injectionRecorder) RecordSecretInput(context.Context, proxycore.SecretInputEvidence) error {
	r.calls++
	return nil
}

type injectionAuditor struct{ calls int }

func (a *injectionAuditor) AuditSecretInput(context.Context, proxycore.SecretInputEvidence) error {
	a.calls++
	return nil
}
func (a *injectionAuditor) AuditSecretInputResult(context.Context, proxycore.SecretInputEvidence, bool) error {
	a.calls++
	return nil
}

func TestInjectVaultSecret_FetchesOnlyForRegisteredLiveSession(t *testing.T) {
	material := []byte("vault-secret")
	vault := &injectionVault{material: material}
	registry := infrastructure.NewSecretInputRegistry()
	typer, recorder, auditor := &injectionTyper{}, &injectionRecorder{}, &injectionAuditor{}
	cleanup := registry.Register(context.Background(), "s1", "ssh", "10.0.0.5:22", "root", typer, recorder)
	defer cleanup()
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "")
	srv.SecretInputs = registry
	srv.Fetcher = proxycore.NewCredentialFetcher(vault, "ssh-proxy")
	srv.SecretAuditor = auditor

	body, _ := json.Marshal(map[string]string{"session_id": "s1", "account_id": "acc1", "vault_scope_token": "one-use-scope"})
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/inject-vault-secret", strings.NewReader(string(body))))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("status=%d body=%q", rec.Code, rec.Body.String())
	}
	if string(typer.got) != "vault-secret" || vault.calls != 1 || auditor.calls != 2 || recorder.calls != 1 {
		t.Fatalf("typed=%q vault=%d audit=%d record=%d", typer.got, vault.calls, auditor.calls, recorder.calls)
	}
	for i, b := range material {
		if b != 0 {
			t.Fatalf("material byte %d not purged", i)
		}
	}
}

func TestInjectVaultSecret_InactiveSessionDoesNotBurnVaultScope(t *testing.T) {
	vault := &injectionVault{material: []byte("must-not-fetch")}
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "")
	srv.SecretInputs = infrastructure.NewSecretInputRegistry()
	srv.Fetcher = proxycore.NewCredentialFetcher(vault, "ssh-proxy")
	srv.SecretAuditor = &injectionAuditor{}
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/inject-vault-secret", strings.NewReader(`{"session_id":"missing","account_id":"acc1","vault_scope_token":"scope"}`)))
	if rec.Code != http.StatusNotFound || vault.calls != 0 {
		t.Fatalf("status=%d fetches=%d body=%q", rec.Code, vault.calls, rec.Body.String())
	}
}

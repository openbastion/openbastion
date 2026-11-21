package interfaces_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/interfaces"
)

type screenInjectionVault struct{ fetched proxycore.Fetched }

func (v screenInjectionVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	return v.fetched, nil
}

type screenInjectionAudit struct{}

func (screenInjectionAudit) AuditSecretInput(context.Context, proxycore.SecretInputEvidence) error {
	return nil
}
func (screenInjectionAudit) AuditSecretInputResult(context.Context, proxycore.SecretInputEvidence, bool) error {
	return nil
}
func (screenInjectionAudit) RecordSecretInput(context.Context, proxycore.SecretInputEvidence) error {
	return nil
}

type screenInjectionTyper struct{}

func (screenInjectionTyper) WithExclusiveInput(_ context.Context, operation func() error) error {
	return operation()
}
func (screenInjectionTyper) TypeSecret(context.Context, []byte) error { return nil }

func TestInjectVaultSecret_RequiresLiveScreenAndNoStore(t *testing.T) {
	registry := infrastructure.NewSecretInputRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unregister := registry.Register(ctx, "session-1", "rdp", "rdp.example:3389", "operator", screenInjectionTyper{}, screenInjectionAudit{})
	defer unregister()
	fetcher := proxycore.NewCredentialFetcher(screenInjectionVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte("vault-secret"), TargetHost: "rdp.example:3389", TargetUser: "operator",
	}}, "rdp-vnc-proxy")
	server := interfaces.NewHTTPServer(nil, nil, nil, nil, "", nil).WithSecretInputs(registry, fetcher, screenInjectionAudit{})
	rec := httptest.NewRecorder()
	server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/inject-vault-secret", strings.NewReader(`{"session_id":"session-1","account_id":"account-prod","vault_scope_token":"one-use"}`)))
	if rec.Code != http.StatusNoContent || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
}

func TestInjectVaultSecret_RejectsInactiveSessionAndUnknownFields(t *testing.T) {
	registry := infrastructure.NewSecretInputRegistry()
	fetcher := proxycore.NewCredentialFetcher(screenInjectionVault{}, "rdp-vnc-proxy")
	server := interfaces.NewHTTPServer(nil, nil, nil, nil, "", nil).WithSecretInputs(registry, fetcher, screenInjectionAudit{})
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"inactive", `{"session_id":"missing","account_id":"account","vault_scope_token":"scope"}`, http.StatusNotFound},
		{"unknown field", `{"session_id":"missing","account_id":"account","vault_scope_token":"scope","secret":"must-not-be-accepted"}`, http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/inject-vault-secret", strings.NewReader(tc.body)))
			if rec.Code != tc.status || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("status=%d want=%d headers=%v", rec.Code, tc.status, rec.Header())
			}
		})
	}
}

// ADR-0133 §2: the Broker's grant of one paste. No text crosses this route, and a text offered in it
// is refused as an unknown field.
func TestAuthorizePaste_TheBrokersGrant(t *testing.T) {
	registry := infrastructure.NewSecretInputRegistry()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	unregister := registry.Register(ctx, "session-1", "rdp", "rdp.example:3389", "operator", screenInjectionTyper{}, screenInjectionAudit{})
	defer unregister()
	server := interfaces.NewHTTPServer(nil, nil, nil, nil, "", nil).WithSecretInputs(registry, nil, screenInjectionAudit{})
	token := strings.Repeat("ab", 32)
	post := func(body string) int {
		rec := httptest.NewRecorder()
		server.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/authorize-paste", strings.NewReader(body)))
		if rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("no Cache-Control: no-store")
		}
		return rec.Code
	}
	grant := `{"session_id":"session-1","account_id":"account-prod","paste_token":"` + token + `","ttl_seconds":60}`
	if code := post(grant); code != http.StatusServiceUnavailable {
		t.Fatalf("without an auditor: %d", code)
	}
	registry.Auditor = screenInjectionAudit{}
	if code := post(grant); code != http.StatusNoContent {
		t.Fatalf("the grant: %d", code)
	}
	for name, c := range map[string]struct {
		body   string
		status int
	}{
		"the same token again": {grant, http.StatusBadRequest},
		"a short token":        {`{"session_id":"session-1","account_id":"a","paste_token":"abcd","ttl_seconds":60}`, http.StatusBadRequest},
		"61 seconds":           {`{"session_id":"session-1","account_id":"a","paste_token":"` + strings.Repeat("cd", 32) + `","ttl_seconds":61}`, http.StatusBadRequest},
		"a text in it":         {`{"session_id":"session-1","account_id":"a","paste_token":"` + strings.Repeat("ef", 32) + `","ttl_seconds":60,"text":"hunter2"}`, http.StatusBadRequest},
		"a session not live":   {`{"session_id":"session-9","account_id":"a","paste_token":"` + strings.Repeat("12", 32) + `","ttl_seconds":60}`, http.StatusNotFound},
	} {
		if code := post(c.body); code != c.status {
			t.Errorf("%s: %d, want %d", name, code, c.status)
		}
	}
	var raw [32]byte
	for i := range raw {
		raw[i] = 0xab
	}
	if account, ok := registry.TakePaste("session-1", raw); !ok || account != "account-prod" {
		t.Fatalf("the granted token: %q %v", account, ok)
	}
}

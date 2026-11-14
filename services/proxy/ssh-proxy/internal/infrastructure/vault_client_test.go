package infrastructure_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
)

func TestVaultCredentialHTTPClient_FetchesCredentialWithBoundedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/vault/v1/fetch-credential" {
			t.Errorf("path=%s", r.URL.Path)
		}
		if r.Header.Get("Cache-Control") != "no-store" {
			t.Errorf("Cache-Control=%q", r.Header.Get("Cache-Control"))
		}
		var request map[string]string
		_ = json.NewDecoder(r.Body).Decode(&request)
		if request["scope_token"] != "scope" || request["calling_proxy_id"] != "ssh-proxy" {
			t.Errorf("request=%v", request)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"credential_type": "password", "credential_material": []byte("secret"), "target_host": "host:22", "target_user": "root"})
	}))
	defer server.Close()
	got, err := (&infrastructure.VaultCredentialHTTPClient{BaseURL: server.URL}).FetchCredential(context.Background(), "scope", "ssh-proxy")
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "password" || string(got.Material) != "secret" || got.TargetHost != "host:22" || got.TargetUser != "root" {
		t.Fatalf("credential=%+v", got)
	}
}

func TestVaultCredentialHTTPClient_RejectsOversizedResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(strings.Repeat("x", (1<<20)+1))) }))
	defer server.Close()
	if _, err := (&infrastructure.VaultCredentialHTTPClient{BaseURL: server.URL}).FetchCredential(context.Background(), "scope", "ssh-proxy"); err == nil {
		t.Fatal("oversized response accepted")
	}
}

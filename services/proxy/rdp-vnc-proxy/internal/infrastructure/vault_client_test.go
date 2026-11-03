package infrastructure

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVaultCredentialHTTPClientCarriesTargetTrustMetadata(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/vault/v1/fetch-credential" {
			t.Errorf("request = %s %s", r.Method, r.URL.Path)
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Error(err)
		}
		if req["scope_token"] != "single-use" || req["calling_proxy_id"] != "rdp-vnc-proxy" {
			t.Errorf("request body: %#v", req)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"credential_type": "password", "credential_material": []byte("credential-data"), "target_host": "desktop:5900", "target_user": "operator", "tls_certificate_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef", "target_domain": "desktop.example"})
	}))
	defer server.Close()
	got, err := (&VaultCredentialHTTPClient{BaseURL: server.URL}).FetchCredential(context.Background(), "single-use", "rdp-vnc-proxy")
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Material) != "credential-data" || got.TargetHost != "desktop:5900" || got.TargetUser != "operator" || got.TLSCertificateSHA256 == "" || got.TargetDomain != "desktop.example" {
		t.Fatalf("fetched credential mismatch: type=%q host=%q user=%q pin=%q domain=%q", got.Type, got.TargetHost, got.TargetUser, got.TLSCertificateSHA256, got.TargetDomain)
	}
}

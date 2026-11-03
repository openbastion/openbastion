package interfaces_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/interfaces"
)

type tlsPinAudit struct{}

func (tlsPinAudit) EmitEvent(context.Context, string, string, string, string, bool) error { return nil }

func TestSetTLSPinHTTPAndFetchCredentialExposePinnedTargetMetadata(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, allowAll{}).WithRotation(nil, tlsPinAudit{})
	if err := svc.OnboardPinned(context.Background(), []string{"admin"}, application.OnboardInput{ID: "vnc-account", Name: "desktop", Username: "operator", TargetHost: "desktop.internal:5900", Protocol: "vnc", Policy: domain.RotationManual, InitialSecret: []byte("vnc-password")}); err != nil {
		t.Fatal(err)
	}
	server := interfaces.NewHTTPServer(svc).Routes()
	missingPinBody := `{"session_id":"session-before-pin","privileged_account_id":"vnc-account","proxy_service_id":"rdp-vnc-proxy","ttl_seconds":60}`
	missingPinReq := httptest.NewRequest(http.MethodPost, "/vault/v1/authorize-scope", strings.NewReader(missingPinBody))
	missingPinResp := httptest.NewRecorder()
	server.ServeHTTP(missingPinResp, missingPinReq)
	if missingPinResp.Code != http.StatusConflict || !strings.Contains(missingPinResp.Body.String(), `"code":"no_pinned_tls_pin"`) {
		t.Fatalf("scope without TLS pin status=%d body=%s", missingPinResp.Code, missingPinResp.Body.String())
	}
	pin := strings.Repeat("a", 64)
	body, _ := json.Marshal(map[string]any{"tlsCertificateSha256": strings.ToUpper(pin), "targetDomain": "DESKTOP.INTERNAL.", "actorRoles": []string{"admin"}, "actorId": "user-admin"})
	req := httptest.NewRequest(http.MethodPut, "/vault/v1/accounts/vnc-account/tls-pin", bytes.NewReader(body))
	resp := httptest.NewRecorder()
	server.ServeHTTP(resp, req)
	if resp.Code != http.StatusOK {
		t.Fatalf("SetTLSPin status=%d body=%s", resp.Code, resp.Body.String())
	}
	var pinResponse struct {
		Fingerprint string `json:"tlsCertificateSha256"`
		Domain      string `json:"targetDomain"`
	}
	if err := json.Unmarshal(resp.Body.Bytes(), &pinResponse); err != nil {
		t.Fatal(err)
	}
	if pinResponse.Fingerprint != pin || pinResponse.Domain != "desktop.internal" {
		t.Fatalf("SetTLSPin response: %+v", pinResponse)
	}

	accountReq := httptest.NewRequest(http.MethodGet, "/vault/v1/accounts/vnc-account", nil)
	accountResp := httptest.NewRecorder()
	server.ServeHTTP(accountResp, accountReq)
	if accountResp.Code != http.StatusOK || !strings.Contains(accountResp.Body.String(), `"tlsCertificateSha256":"`+pin+`"`) || !strings.Contains(accountResp.Body.String(), `"targetDomain":"desktop.internal"`) {
		t.Fatalf("account response status=%d body=%s", accountResp.Code, accountResp.Body.String())
	}

	scope, _, err := svc.AuthorizeScope(context.Background(), "session", "vnc-account", "rdp-vnc-proxy", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	fetchBody, _ := json.Marshal(map[string]string{"scope_token": scope, "calling_proxy_id": "rdp-vnc-proxy"})
	fetchReq := httptest.NewRequest(http.MethodPost, "/vault/v1/fetch-credential", bytes.NewReader(fetchBody))
	fetchResp := httptest.NewRecorder()
	server.ServeHTTP(fetchResp, fetchReq)
	if fetchResp.Code != http.StatusOK {
		t.Fatalf("FetchCredential status=%d body=%s", fetchResp.Code, fetchResp.Body.String())
	}
	var delivered struct {
		Material    []byte `json:"credential_material"`
		TargetHost  string `json:"target_host"`
		TargetUser  string `json:"target_user"`
		Fingerprint string `json:"tls_certificate_sha256"`
		Domain      string `json:"target_domain"`
	}
	if err := json.Unmarshal(fetchResp.Body.Bytes(), &delivered); err != nil {
		t.Fatal(err)
	}
	if string(delivered.Material) != "vnc-password" || delivered.TargetHost != "desktop.internal:5900" || delivered.TargetUser != "operator" || delivered.Fingerprint != pin || delivered.Domain != "desktop.internal" {
		t.Fatalf("delivered metadata mismatch: %+v", delivered)
	}
}

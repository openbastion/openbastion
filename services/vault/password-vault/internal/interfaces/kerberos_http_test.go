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

// ADR-0100: PUT /vault/v1/accounts/{id}/kerberos sets the realm and KDCs, normalized; the account
// shows them; fetch-credential hands them to the proxy with the secret; null removes them.
func TestSetKerberosHTTP_AndFetchCredentialHandsThemToTheProxy(t *testing.T) {
	kms, err := infrastructure.NewLocalKMS()
	if err != nil {
		t.Fatal(err)
	}
	store := infrastructure.NewInMemoryStore()
	svc := application.NewVaultService(store, store, store, kms, allowAll{}).WithRotation(nil, tlsPinAudit{})
	ctx := context.Background()
	if err := svc.OnboardPinned(ctx, []string{"admin"}, application.OnboardInput{ID: "desk", Name: "desk", Username: "operator", TargetHost: "desk.corp.example.com:3389", Protocol: "rdp", Policy: domain.RotationManual, InitialSecret: []byte("rdp-password")}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.SetTLSPin(ctx, "admin", []string{"admin"}, "desk", strings.Repeat("a", 64), "desk.corp.example.com"); err != nil {
		t.Fatal(err)
	}
	server := interfaces.NewHTTPServer(svc).Routes()
	put := func(body string) *httptest.ResponseRecorder {
		resp := httptest.NewRecorder()
		server.ServeHTTP(resp, httptest.NewRequest(http.MethodPut, "/vault/v1/accounts/desk/kerberos", strings.NewReader(body)))
		return resp
	}
	for name, body := range map[string]string{
		"an unknown field": `{"kerberos": {"realm": "CORP", "kdcs": ["dc1"]}, "spn": "TERMSRV/other", "actorRoles": ["admin"], "actorId": "a"}`,
		"no KDC":           `{"kerberos": {"realm": "CORP", "kdcs": []}, "actorRoles": ["admin"], "actorId": "a"}`,
		"a URL":            `{"kerberos": {"realm": "CORP", "kdcs": ["tcp://dc1:88"]}, "actorRoles": ["admin"], "actorId": "a"}`,
	} {
		if resp := put(body); resp.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", name, resp.Code, resp.Body.String())
		}
	}
	resp := put(`{"kerberos": {"realm": "corp.example.com", "kdcs": ["DC1.corp.example.com", "10.0.0.4:88"]}, "actorRoles": ["admin"], "actorId": "user-admin"}`)
	if resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"realm":"CORP.EXAMPLE.COM"`) || !strings.Contains(resp.Body.String(), `"dc1.corp.example.com:88"`) {
		t.Fatalf("set: %d %s", resp.Code, resp.Body.String())
	}
	account := httptest.NewRecorder()
	server.ServeHTTP(account, httptest.NewRequest(http.MethodGet, "/vault/v1/accounts/desk", nil))
	if !strings.Contains(account.Body.String(), `"kerberos":{"realm":"CORP.EXAMPLE.COM","kdcs":["dc1.corp.example.com:88","10.0.0.4:88"]}`) {
		t.Fatalf("the account: %s", account.Body.String())
	}

	fetch := func() map[string]any {
		scope, _, err := svc.AuthorizeScope(ctx, "session-"+time.Now().Format("150405.000000000"), "desk", "rdp-vnc-proxy", time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := json.Marshal(map[string]string{"scope_token": scope, "calling_proxy_id": "rdp-vnc-proxy"})
		resp := httptest.NewRecorder()
		server.ServeHTTP(resp, httptest.NewRequest(http.MethodPost, "/vault/v1/fetch-credential", bytes.NewReader(body)))
		if resp.Code != http.StatusOK {
			t.Fatalf("fetch: %d %s", resp.Code, resp.Body.String())
		}
		var out map[string]any
		_ = json.Unmarshal(resp.Body.Bytes(), &out)
		return out
	}
	delivered := fetch()
	if delivered["kerberos_realm"] != "CORP.EXAMPLE.COM" || len(delivered["kerberos_kdcs"].([]any)) != 2 {
		t.Fatalf("delivered: %v", delivered)
	}

	if resp := put(`{"kerberos": null, "actorRoles": ["admin"], "actorId": "user-admin"}`); resp.Code != http.StatusOK || !strings.Contains(resp.Body.String(), `"kerberos":null`) {
		t.Fatalf("removed: %d %s", resp.Code, resp.Body.String())
	}
	if delivered := fetch(); delivered["kerberos_realm"] != nil || delivered["kerberos_kdcs"] != nil {
		t.Fatalf("NTLM accounts carry no Kerberos fields: %v", delivered)
	}
}

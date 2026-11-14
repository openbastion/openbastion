package interfaces_test

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecretInjectionStepUp_GatewayInjectsVerifiedIdentityAndDoesNotRelayClientBody(t *testing.T) {
	gw, broker := sessionGateway(t)
	req := httptest.NewRequest(http.MethodPost, "/sessions/s-1/secret-injection-step-up", nil)
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d Cache-Control=%q body=%q", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 || got[0].path != "/sessions/s-1/secret-injection-step-up" {
		t.Fatalf("Broker requests: %+v", got)
	}
	if len(got[0].body) != 2 || got[0].body["callerId"] != "u-alice" {
		t.Fatalf("Broker received identity/body %#v", got[0].body)
	}
	roles, _ := got[0].body["actorRoles"].([]any)
	if len(roles) != 2 || roles[0] != "sre" || roles[1] != "breakglass-requester" {
		t.Fatalf("Broker roles = %#v", roles)
	}
}

func TestSecretInjection_GatewayForwardsOnlyMFAProofAndVerifiedIdentity(t *testing.T) {
	gw, broker := sessionGateway(t)
	body := `{"challenge":"opaque-challenge","factor":"totp","totp_code":"123456"}`
	rec := do(gw, http.MethodPost, "/sessions/s-1/secret-injection", body, true)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d Cache-Control=%q body=%q", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 || got[0].path != "/sessions/s-1/secret-injection" || got[0].method != http.MethodPost {
		t.Fatalf("Broker requests: %+v", got)
	}
	b := got[0].body
	if len(b) != 5 || b["callerId"] != "u-alice" || b["challenge"] != "opaque-challenge" || b["factor"] != "totp" || b["totp_code"] != "123456" {
		t.Fatalf("Broker received unexpected fields: %#v", b)
	}
	roles, _ := b["actorRoles"].([]any)
	if len(roles) != 2 || roles[0] != "sre" || roles[1] != "breakglass-requester" {
		t.Fatalf("Broker roles = %#v", roles)
	}
	if _, ok := b["accountId"]; ok {
		t.Fatalf("client account id reached Broker: %#v", b)
	}
	if _, ok := b["grant"]; ok {
		t.Fatalf("grant reached Broker from client: %#v", b)
	}
}

func TestSecretInjection_GatewayRejectsForgedIdentityFieldsAndUnknownActions(t *testing.T) {
	gw, broker := sessionGateway(t)
	for name, body := range map[string]string{
		"forged caller": `{"callerId":"u-victim","challenge":"c","factor":"totp","totp_code":"123456"}`,
		"forged roles":  `{"actorRoles":["platform-admin"],"challenge":"c","factor":"totp","totp_code":"123456"}`,
		"secret field":  `{"challenge":"c","factor":"totp","totp_code":"123456","secret":"target-password"}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := do(gw, http.MethodPost, "/sessions/s-1/secret-injection", body, true)
			if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("got %d Cache-Control=%q %q", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
			}
		})
	}
	if rec := do(gw, http.MethodPost, "/sessions/s-1/secret-injection-step-up", `{"callerId":"u-victim"}`, true); rec.Code != http.StatusBadRequest {
		t.Fatalf("step-up accepted a client body: %d %q", rec.Code, rec.Body.String())
	}
	if rec := do(gw, http.MethodPost, "/sessions/s-1/secret-injection/extra", `{}`, true); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown deeper route: %d", rec.Code)
	}
	if got := broker.requests(); len(got) != 0 {
		t.Fatalf("invalid requests reached Broker: %+v", got)
	}
}

func TestSecretInjection_GatewayRequiresBearerToken(t *testing.T) {
	gw, broker := sessionGateway(t)
	for _, path := range []string{"/sessions/s-1/secret-injection-step-up", "/sessions/s-1/secret-injection"} {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{"challenge":"c","factor":"totp","totp_code":"123456"}`))
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without token: %d", path, rec.Code)
		}
	}
	if got := broker.requests(); len(got) != 0 {
		t.Fatalf("unauthenticated requests reached Broker: %+v", got)
	}
}

func TestSecretInjection_GatewayWebAuthnProofIsForwardedAsJSON(t *testing.T) {
	gw, broker := sessionGateway(t)
	body := `{"challenge":"opaque-challenge","factor":"webauthn","webauthn_response":{"id":"credential-id","response":{"clientDataJSON":"YQ=="}}}`
	rec := do(gw, http.MethodPost, "/sessions/s-1/secret-injection", body, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 {
		t.Fatalf("Broker requests: %+v", got)
	}
	encoded, err := json.Marshal(got[0].body["webauthn_response"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(encoded), "credential-id") {
		t.Fatalf("WebAuthn response was not preserved: %s", encoded)
	}
}

type failingRequestBody struct{}

func (failingRequestBody) Read([]byte) (int, error) {
	return 0, errors.New("simulated body read failure")
}
func (failingRequestBody) Close() error { return nil }

func TestSecretInjectionStepUp_GatewayFailsClosedWhenBodyCannotBeRead(t *testing.T) {
	gw, broker := sessionGateway(t)
	req := httptest.NewRequest(http.MethodPost, "/sessions/s-1/secret-injection-step-up", nil)
	req.Body = io.NopCloser(failingRequestBody{})
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d Cache-Control=%q body=%q", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	if got := broker.requests(); len(got) != 0 {
		t.Fatalf("unread request body reached Broker: %+v", got)
	}
}

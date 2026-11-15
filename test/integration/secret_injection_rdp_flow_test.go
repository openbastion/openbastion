package integration_test

import (
	"bytes"
	"net/http"
	"testing"
	"time"
)

// injectRDPVaultSecret exercises the real Broker -> Vault -> RDP Proxy path with action-level TOTP.
// The Windows CI test separately verifies that the Unicode keyboard events are accepted by Windows.
func injectRDPVaultSecret(t *testing.T, stack *rdpScreenStack, sessionID string) {
	t.Helper()
	api := stack.api.in(t)
	if status, _ := api.call(stack.operatorToken, http.MethodPost, "/sessions/"+sessionID+"/secret-injection-step-up", nil); status != http.StatusForbidden {
		t.Fatalf("non-owner RDP step-up returned %d, want 403", status)
	}
	waitForTOTPStep(t, stack.enrollmentStep+1)
	code := totpCode(t, stack.totpSecret, time.Unix((stack.enrollmentStep+1)*30+1, 0))
	badCode := "000000"
	if code == badCode {
		badCode = "000001"
	}
	requestStepUp := func() string {
		resp, body := api.do(stack.stepUpToken, http.MethodPost, "/sessions/"+sessionID+"/secret-injection-step-up", nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("RDP step-up: %d %s", resp.StatusCode, body)
		}
		return jsonField(t, body, "challenge")
	}
	prove := func(challenge, proof string) (int, string) {
		return api.call(stack.stepUpToken, http.MethodPost, "/sessions/"+sessionID+"/secret-injection", map[string]any{
			"challenge": challenge, "factor": "totp", "totp_code": proof,
		})
	}
	if status, _ := prove(requestStepUp(), badCode); status != http.StatusForbidden {
		t.Fatalf("invalid RDP TOTP proof returned %d, want 403", status)
	}
	if status, body := prove(requestStepUp(), code); status != http.StatusNoContent || body != "" {
		t.Fatalf("RDP Vault injection: %d %s", status, body)
	}
	if !stack.audit.saw("session.secret_injected", sessionID) {
		t.Fatal("successful RDP injection is missing from the Audit Service")
	}
	status, body := api.call(stack.auditorToken, http.MethodGet, "/sessions/"+sessionID+"/recording/video/events?limit=100", nil)
	if status != http.StatusOK || bytes.Contains([]byte(body), []byte(freeRDPPassword)) || !bytes.Contains([]byte(body), []byte("secret_injection_started")) {
		t.Fatalf("RDP video marker missing or secret disclosed: %d %s", status, body)
	}
	if stack.store.holds([]byte(freeRDPPassword)) {
		t.Fatal("the object store contains the RDP Vault secret in clear")
	}
}

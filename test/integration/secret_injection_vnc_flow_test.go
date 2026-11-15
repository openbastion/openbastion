package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func testScreenVaultSecretInjection(t *testing.T, gatewayURL, authnURL string, admin *http.Client, api screenAPI, operatorToken, auditorToken string, target *fakeRFBTarget, audit *screenAuditSpy, store *fakeObjectStore, outputs map[string]*syncBuffer) {
	t.Helper()
	const username, password = "screen-stepup", "stepup-password-123"
	token, totpSecret, loginStep := mfaStepUpToken(t, gatewayURL, authnURL, admin, username, password)
	status, raw := api.in(t).call(token, http.MethodPost, "/sessions", map[string]any{"targetAccountId": "screen_good", "protocol": "vnc", "justification": "ADR-0097 integration", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("create VNC session: %d %s", status, raw)
	}
	sessionID := jsonField(t, raw, "id")
	attach := api.in(t).connect(token, sessionID)
	conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	if hello := readScreen(t, conn); hello.kind != 2 || hello.helloSession != sessionID {
		t.Fatalf("screen did not become active: %+v", hello)
	}
	_ = readFrame(t, conn)
	defer func() { _, _ = api.in(t).call(token, http.MethodDelete, "/sessions/"+sessionID, nil) }()
	if status, _ := api.in(t).call(operatorToken, http.MethodPost, "/sessions/"+sessionID+"/secret-injection-step-up", nil); status != http.StatusForbidden {
		t.Fatalf("non-owner step-up returned %d, want 403", status)
	}
	requestStepUp := func() string {
		resp, body := api.in(t).do(token, http.MethodPost, "/sessions/"+sessionID+"/secret-injection-step-up", nil)
		if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
			t.Fatalf("step-up: %d %s", resp.StatusCode, body)
		}
		return jsonField(t, body, "challenge")
	}
	prove := func(challenge, code string) (int, string) {
		return api.in(t).call(token, http.MethodPost, "/sessions/"+sessionID+"/secret-injection", map[string]any{"challenge": challenge, "factor": "totp", "totp_code": code})
	}
	waitForTOTPStep(t, loginStep+1)
	badCode := totpCode(t, totpSecret, time.Unix((loginStep+1)*30+1, 0))
	if badCode == "000000" {
		badCode = "000001"
	} else {
		badCode = "000000"
	}
	if status, _ := prove(requestStepUp(), badCode); status != http.StatusForbidden {
		t.Fatalf("invalid TOTP proof returned %d, want 403", status)
	}
	if got := target.keySequence(); len(got) != 0 {
		t.Fatalf("target received key events after a refused MFA proof: %v", got)
	}
	challenge := requestStepUp()
	if status, body := prove(challenge, totpCode(t, totpSecret, time.Unix((loginStep+1)*30+1, 0))); status != http.StatusNoContent || body != "" {
		t.Fatalf("Vault injection: %d %s", status, body)
	}
	const vaultSecret = "VNC-秘密-42"
	want := make([]uint32, 0, len([]rune(vaultSecret)))
	for _, r := range vaultSecret {
		keysym := uint32(r)
		if r > 0xff {
			keysym = 0x01000000 + uint32(r)
		}
		want = append(want, keysym)
	}
	waitUntil(t, 5*time.Second, "the complete Unicode secret to reach the VNC target", func() bool { return len(target.keySequence()) >= len(want) })
	got := target.keySequence()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("VNC target keysyms = %v, want Unicode sequence %v", got, want)
	}
	if !audit.saw("session.secret_injected", sessionID) {
		t.Fatal("successful injection is missing from the Audit Service")
	}
	status, body := api.in(t).call(auditorToken, http.MethodGet, "/sessions/"+sessionID+"/recording/video/events?limit=100", nil)
	if status != http.StatusOK || strings.Contains(body, vaultSecret) || !strings.Contains(body, "secret_injection_started") {
		t.Fatalf("video event marker missing or secret disclosed: %d %s", status, body)
	}
	if store.holds([]byte(vaultSecret)) {
		t.Fatal("the object store contains the Vault secret in clear")
	}
	for name, output := range outputs {
		if strings.Contains(output.String(), vaultSecret) {
			t.Fatalf("Vault secret leaked to %s logs", name)
		}
	}
}

func mfaStepUpToken(t *testing.T, gatewayURL, authnURL string, admin *http.Client, username, password string) (string, string, int64) {
	t.Helper()
	status, login := postJSONTo(t, gatewayURL+"/auth/login", map[string]string{"username": username, "password": password})
	if status != http.StatusUnauthorized || login["mfa"] != "enrollment_required" || login["challenge"] == nil {
		t.Fatalf("MFA enrollment challenge: %d %#v", status, login)
	}
	loginChallenge := login["challenge"].(string)
	raw, _ := json.Marshal(map[string]string{"source": "local", "loginName": username})
	req, err := http.NewRequest(http.MethodPost, authnURL+"/auth/v1/mfa/enrollment-codes", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := admin.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	var issued map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&issued)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || issued["enrollmentCode"] == nil {
		t.Fatalf("issue TOTP enrollment code: %d %#v", resp.StatusCode, issued)
	}
	status, enrolled := postJSONTo(t, gatewayURL+"/auth/mfa/enroll", map[string]string{"challenge": loginChallenge, "enrollmentCode": issued["enrollmentCode"].(string), "factor": "totp"})
	if status != http.StatusOK || enrolled["secret"] == nil {
		t.Fatalf("enroll TOTP: %d %#v", status, enrolled)
	}
	totpSecret := enrolled["secret"].(string)
	enrollmentStep := time.Now().Unix() / 30
	status, confirmed := postJSONTo(t, gatewayURL+"/auth/mfa/enroll/confirm", map[string]string{"challenge": loginChallenge, "code": totpCode(t, totpSecret, time.Unix(enrollmentStep*30+1, 0))})
	if status != http.StatusOK || confirmed["accessToken"] == nil {
		t.Fatalf("confirm TOTP: %d %#v", status, confirmed)
	}
	return confirmed["accessToken"].(string), totpSecret, enrollmentStep
}

package integration_test

// ADR-0133 across real processes: an operator's password, typed into a VNC session by the proxy.
// The Gateway, the Broker, the screen proxy, the Video Recorder and the Audit Service are the real
// ones of TestScreenFlow_VNCFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses; the client is
// pkg/proxycore.SealPaste, the same encryption as the Admin UI's (their known-answer vector is
// shared: pkg/proxycore/paste_vector_test.go, web/admin-ui/src/features/screen/pasteCrypto.test.ts).
//
// The claims: the target receives the password, key by key; the API saw only the factor's proof;
// a replayed message, a message without a token, and a message for another session type nothing and
// are audited as refused; the recording keeps only the size and a salted fingerprint; no log, no
// stored object and no audit event holds the password.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

func testScreenOperatorPaste(t *testing.T, gatewayURL string, api screenAPI, operatorToken, auditorToken string, mfa *mfaStepUpCredentials, target secretInputObserver, accountID, password string, audit *screenAuditSpy, store *fakeObjectStore, outputs map[string]*syncBuffer) {
	t.Helper()
	token := mfa.token
	defer func() {
		if t.Failed() {
			for _, name := range []string{"screen-proxy", "gateway"} {
				if out := outputs[name]; out != nil {
					t.Logf("%s:\n%s", name, tail(out.String(), 3000))
				}
			}
		}
	}()
	status, raw := api.in(t).call(token, http.MethodPost, "/sessions", map[string]any{"targetAccountId": accountID, "protocol": "vnc", "justification": "ADR-0133 integration", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("create VNC session: %d %s", status, raw)
	}
	sessionID := jsonField(t, raw, "id")
	defer func() { _, _ = api.in(t).call(token, http.MethodDelete, "/sessions/"+sessionID, nil) }()
	attach := api.in(t).connect(token, sessionID)
	conn := dialScreen(t, gatewayURL, attach.path, attach.cookie)
	defer conn.Close(websocket.StatusNormalClosure, "")
	hello := readScreen(t, conn)
	if hello.kind != 2 || hello.helloSession != sessionID || hello.helloFlags&helloPaste == 0 || len(hello.helloPasteKey) != 65 {
		t.Fatalf("the HELLO carries no paste key: %+v", hello)
	}
	_ = readFrame(t, conn)
	before := len(target.keySequence())
	send := func(in screenstream.PasteInput) {
		t.Helper()
		data, err := screenstream.EncodePasteInput(in)
		if err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := conn.Write(ctx, websocket.MessageBinary, data); err != nil {
			t.Fatalf("send the paste: %v", err)
		}
	}
	seal := func(tokenHex, session string) screenstream.PasteInput {
		t.Helper()
		var pasteToken [screenstream.PasteTokenSize]byte
		raw, err := hex.DecodeString(tokenHex)
		if err != nil || copy(pasteToken[:], raw) != len(pasteToken) {
			t.Fatalf("paste token %q", tokenHex)
		}
		in, err := proxycore.SealPaste(hello.helloPasteKey, session, "vnc", pasteToken, []byte(password))
		if err != nil {
			t.Fatal(err)
		}
		return in
	}
	refusals := func() int {
		audit.mu.Lock()
		defer audit.mu.Unlock()
		n := 0
		for _, event := range audit.events {
			if strings.Contains(event, `"session.secret_paste_refused"`) && strings.Contains(event, sessionID) {
				n++
			}
		}
		return n
	}

	// Without a factor, a made-up token types nothing.
	send(seal(strings.Repeat("ab", 32), sessionID))
	waitUntil(t, 10*time.Second, "the refusal of a paste without a token", func() bool { return refusals() == 1 })

	// Only the session's requester may ask for the factor, as for a Vault secret.
	if status, _ := api.in(t).call(operatorToken, http.MethodPost, "/sessions/"+sessionID+"/secret-paste-step-up", nil); status != http.StatusForbidden {
		t.Fatalf("another user's paste step-up: %d, want 403", status)
	}
	resp, body := api.in(t).do(token, http.MethodPost, "/sessions/"+sessionID+"/secret-paste-step-up", nil)
	if resp.StatusCode != http.StatusOK || resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("paste step-up: %d %s", resp.StatusCode, body)
	}
	challenge := jsonField(t, body, "challenge")
	step := mfa.step + 1
	waitForTOTPStep(t, step)
	status, grant := api.in(t).call(token, http.MethodPost, "/sessions/"+sessionID+"/secret-paste",
		map[string]any{"challenge": challenge, "factor": "totp", "totp_code": totpCode(t, mfa.totpSecret, time.Unix(step*30+1, 0))})
	mfa.step = step
	if status != http.StatusOK {
		t.Fatalf("paste grant: %d %s", status, grant)
	}
	pasteToken := jsonField(t, grant, "pasteToken")
	// The Broker audits the grant to the Audit Service directly, not through the proxy's spy: its
	// unit test (operator_paste_test.go) proves it; here, the proxy's events are the ones read.

	// Sealed for another session, the right token opens nothing, and burns the token.
	sealed := seal(pasteToken, sessionID)
	wrong := seal(pasteToken, sessionID+"-other")
	send(wrong)
	waitUntil(t, 10*time.Second, "the refusal of a paste sealed for another session", func() bool { return refusals() == 2 })
	if got := target.keySequence(); len(got) != before {
		t.Fatalf("the target received keys from a refused paste: %v", got[before:])
	}

	// A second factor, a second token: this one types the password.
	resp, body = api.in(t).do(token, http.MethodPost, "/sessions/"+sessionID+"/secret-paste-step-up", nil)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("second paste step-up: %d %s", resp.StatusCode, body)
	}
	challenge = jsonField(t, body, "challenge")
	step = mfa.step + 1
	waitForTOTPStep(t, step)
	status, grant = api.in(t).call(token, http.MethodPost, "/sessions/"+sessionID+"/secret-paste",
		map[string]any{"challenge": challenge, "factor": "totp", "totp_code": totpCode(t, mfa.totpSecret, time.Unix(step*30+1, 0))})
	mfa.step = step
	if status != http.StatusOK {
		t.Fatalf("second paste grant: %d %s", status, grant)
	}
	sealed = seal(jsonField(t, grant, "pasteToken"), sessionID)
	send(sealed)
	want := make([]uint32, 0, len([]rune(password)))
	for _, r := range password {
		keysym := uint32(r)
		if r > 0xff {
			keysym = 0x01000000 + uint32(r)
		}
		want = append(want, keysym)
	}
	waitUntil(t, 10*time.Second, "the password at the VNC target", func() bool { return len(target.keySequence()) >= before+len(want) })
	if got := target.keySequence()[before:]; fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("VNC target keysyms = %v, want %v", got, want)
	}
	if !audit.saw("session.secret_pasted", sessionID) {
		t.Fatal("the typed paste is not audited")
	}
	// The same message again: its token is taken, nothing is typed.
	typed := len(target.keySequence())
	send(sealed)
	waitUntil(t, 10*time.Second, "the refusal of a replayed paste", func() bool { return refusals() == 3 })
	if got := len(target.keySequence()); got != typed {
		t.Fatalf("a replayed paste typed %d key(s)", got-typed)
	}

	// The recording: the marker, the size and the salted fingerprint, never the password. The
	// fingerprint is SHA-256(salt‖password): whoever knows the password can check it, nobody can
	// read it back, and the salt keeps two inputs of the same password apart.
	status, events := api.in(t).call(auditorToken, http.MethodGet, "/sessions/"+sessionID+"/recording/video/events?limit=100", nil)
	if status != http.StatusOK || strings.Contains(events, password) {
		t.Fatalf("the recording's events: %d %s", status, events)
	}
	var recorded struct {
		Events []struct {
			EventType   string `json:"eventType"`
			Source      string `json:"source"`
			PasteBytes  int    `json:"pasteBytes"`
			PasteSalt   string `json:"pasteSalt"`
			PasteSHA256 string `json:"pasteSha256"`
		} `json:"events"`
	}
	if err := json.Unmarshal([]byte(events), &recorded); err != nil {
		t.Fatal(err)
	}
	markers := 0
	for _, e := range recorded.Events {
		if e.EventType != "secret_paste_started" {
			continue
		}
		markers++
		salt, err := hex.DecodeString(e.PasteSalt)
		if err != nil || len(salt) != 16 {
			t.Fatalf("paste salt %q", e.PasteSalt)
		}
		sum := sha256.Sum256(append(salt, password...))
		if e.Source != "operator" || e.PasteBytes != len(password) || e.PasteSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("the paste marker: %+v", e)
		}
	}
	if markers != 1 {
		t.Fatalf("%d paste marker(s), want one: the refused pastes are not in the recording", markers)
	}
	if store.holds([]byte(password)) {
		t.Fatal("the object store holds the password in clear")
	}
	audit.mu.Lock()
	for _, event := range audit.events {
		if strings.Contains(event, password) {
			audit.mu.Unlock()
			t.Fatalf("an audit event holds the password: %s", event)
		}
	}
	audit.mu.Unlock()
	for name, output := range outputs {
		if strings.Contains(output.String(), password) {
			t.Fatalf("the password leaked to the %s logs", name)
		}
	}
}

func tail(s string, n int) string {
	if len(s) > n {
		return s[len(s)-n:]
	}
	return s
}

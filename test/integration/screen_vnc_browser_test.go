package integration_test

// A VNC screen through the Admin UI, in a real browser: the services of the screen flow on real
// processes, the built Admin UI served by the Gateway under its strict policy (ADMIN_UI_DIR), and
// a headless Chrome that logs in, finds the session on the Sessions page, opens its screen, sees
// the first frame, types a key that the target itself testifies to, and sees the screen end when
// the session is terminated. Then ADR-0133 in one piece: an operator with a second factor types a
// password through the page's button, and the target receives it. The VNC tests of screen_flow_test.go prove the protocol and its
// refusals through the public API; this one proves that the operator's page reaches them.
//
// The target is the real TigerVNC of the PostgreSQL CI job (OPENBASTION_VNC_TARGET, its X11 input
// oracle), or the fake RFB target of screen_flow_test.go without it. Skipped without
// TEST_DATABASE_URL (the Video Recorder), the built Admin UI (make ui-build), or a Chrome.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestScreenFlow_VNCInAHeadlessBrowser(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: the Video Recorder needs PostgreSQL")
	}
	root := repoRoot(t)
	ui := filepath.Join(root, "web", "admin-ui", "dist")
	if _, err := os.Stat(filepath.Join(ui, "index.html")); err != nil {
		t.Skip("the Admin UI is not built (make ui-build)")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome: set CHROME, or put google-chrome or chromium on PATH")
	}

	// The VNC target, real or fake: where it is, what it holds, its pin, and what it saw typed.
	const fakeSecret = "VNC-browser-42"
	var (
		address, user, secret string
		certPEM               []byte
		pin                   *pinnedTarget
		keys                  func() []uint32
	)
	if real := realVNCTargetFromEnv(t); real != nil {
		address, user, secret, certPEM, pin, keys = real.address, real.user, real.password, real.certPEM, real.pin(), real.keySequence
		t.Logf("the real VNC target at %s", address)
	} else {
		fake := newFakeRFBTarget(t, "vnc-target.test", fakeSecret)
		address, user, secret, certPEM, pin, keys = fake.address, "operator", fakeSecret, fake.certPEM, fake.pin(), fake.keySequence
		t.Logf("the fake RFB target at %s", address)
	}

	// The screen stack of the RDP flow serves VNC too: its acc_rdp is onboarded and never used.
	stack := startRDPScreenStack(t, root, dsn, rdpStackTarget{address: "127.0.0.1:9", pin: pin.fingerprint, serverName: pin.domain,
		user: "unused", password: "unused", certPEM: certPEM}, nil, []string{"ADMIN_UI_DIR=" + ui})
	status, raw := stack.api.call(stack.adminToken, http.MethodPost, "/vault/accounts", map[string]any{
		"id": "acc_vnc", "name": "acc_vnc", "username": user, "targetHost": address, "protocol": "vnc", "rotationPolicy": "manual", "initialSecret": []byte(secret),
	})
	if status != http.StatusCreated {
		t.Fatalf("onboarding the VNC account: %d %s", status, raw)
	}
	status, raw = stack.api.call(stack.adminToken, http.MethodPut, "/vault/accounts/acc_vnc/tls-pin", map[string]any{"tlsCertificateSha256": pin.fingerprint, "targetDomain": pin.domain})
	if status != http.StatusOK {
		t.Fatalf("pinning the VNC account: %d %s", status, raw)
	}
	status, raw = stack.api.call(stack.operatorToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_vnc", "protocol": "vnc", "justification": "VNC through the Admin UI", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("VNC session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")

	dump := os.Getenv("VNC_BROWSER_DUMP")
	page := startHeadlessChrome(t, chrome)
	page.dump = dump
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": stack.gatewayURL + "/ui/"})
	page.signIn("rdp-operator", "op-password-123")
	page.showSession(id)
	page.openScreen()
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 60*time.Second)
	if string(page.eval(screenEndedNotice)) == "true" {
		t.Fatal("the screen shows its end with its first frame")
	}
	// A VNC session has no Ctrl+Alt+Suppr: that button is RDP's.
	if string(page.eval(`[...document.querySelectorAll(".screen button")].some((b) => b.innerText.trim() === "Ctrl+Alt+Suppr")`)) == "true" {
		t.Fatal("the VNC screen offers Ctrl+Alt+Suppr")
	}
	page.eval(`document.querySelector("canvas.screen-canvas").scrollIntoView({ block: "center" }), true`)
	page.screenshot(dump, "vnc-browser-1-first-frame.png")

	// A key typed on the canvas, as a person does: focused by a click, then pressed. The target
	// says it received the keysym of "a" (0x61); the page holds nothing of it.
	var at []float64
	if err := json.Unmarshal(page.eval(`(() => { const c = document.querySelector("canvas.screen-canvas"); const r = c.getBoundingClientRect();
		const x = r.left + r.width / 2, y = r.top + r.height / 2; return document.elementFromPoint(x, y) === c ? [x, y] : null; })()`), &at); err != nil || len(at) != 2 {
		page.screenshot(dump, "vnc-browser-canvas-hidden.png")
		t.Fatalf("the canvas is not where the page shows it: %v %v", at, err)
	}
	page.clickAt(at[0], at[1])
	page.press(cdpKeyA)
	waitUntil(t, 15*time.Second, "the key typed in the page, received by the target", func() bool { return slices.Contains(keys(), 0x61) })

	// The session terminated: the proxy ends the screen, and the page says so.
	status, raw = stack.api.call(stack.operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	if status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, raw)
	}
	page.waitTrue("the screen's end, shown by the page", screenEndedNotice, 30*time.Second)
	page.screenshot(dump, "vnc-browser-2-ended.png")

	t.Run("an operator's password, from the page's button to the target (ADR-0133)", func(t *testing.T) {
		vncOperatorPasteInTheBrowser(t, stack, chrome, dump, keys)
	})
}

// vncOperatorPasteInTheBrowser is ADR-0133 in one piece: the built Admin UI in Chrome, served by the
// Gateway, the real services, the target. An operator with a second factor signs in, opens the screen
// of their session, types a password in the page's masked field, confirms with the factor; the
// target receives it key by key; the recording keeps only its size and salted fingerprint; nothing
// else holds it.
func vncOperatorPasteInTheBrowser(t *testing.T, stack *rdpScreenStack, chrome, dump string, keys func() []uint32) {
	const password = "Browser-Paste-7"
	if status := gatewayCreatePolicy(t, stack.gatewayURL, stack.adminToken, "vnc-stepup-paste", "rdp-stepup", "secret:paste:account:acc_vnc", "allow", "ignored"); status != http.StatusCreated {
		t.Fatalf("paste policy: %d", status)
	}
	status, raw := stack.api.call(stack.stepUpToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_vnc", "protocol": "vnc", "justification": "ADR-0133 through the Admin UI", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("VNC session for the paste: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")
	defer func() { _, _ = stack.api.call(stack.stepUpToken, http.MethodDelete, "/sessions/"+id, nil) }()
	// What the target received, without the modifiers a real X server adds (typedKeys).
	typed := func() []uint32 {
		var out []uint32
		for _, k := range keys() {
			if k < 0xffe1 || k > 0xffee {
				out = append(out, k)
			}
		}
		return out
	}

	// Signing in: the password, then the second factor, as a person does.
	page := startHeadlessChrome(t, chrome)
	page.dump = dump
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": stack.gatewayURL + "/ui/"})
	page.waitTrue("the login form", `!!document.querySelector('input[name="username"]')`, 30*time.Second)
	page.fill(`input[name="username"]`, "rdp-stepup")
	page.fill(`input[name="password"]`, "stepup-password-123")
	page.clickButton("Se connecter")
	page.waitTrue("the login's second factor", `!!document.querySelector('#second-factor-code')`, 20*time.Second)
	step := stack.enrollmentStep + 1
	waitForTOTPStep(t, step)
	page.fill("#second-factor-code", totpCode(t, stack.totpSecret, time.Unix(step*30+1, 0)))
	page.clickButton("Vérifier et continuer")
	page.waitTrue("the sections", `[...document.querySelectorAll("nav button")].some((b) => b.innerText.trim() === "Sessions")`, 30*time.Second)
	page.showSession(id)
	page.openScreen()
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 60*time.Second)
	before := len(typed())

	// The page's button, its masked field, its second factor.
	page.waitTrue("the paste button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Saisir un mot de passe…")`, 15*time.Second)
	page.clickButton("Saisir un mot de passe…")
	page.waitTrue("the masked field", `document.querySelector('#operator-paste-password')?.type === "password"`, 10*time.Second)
	page.fill("#operator-paste-password", password)
	page.clickButton("Continuer")
	page.waitTrue("the paste's second factor", `!!document.querySelector('input[name="totp_code"]')`, 15*time.Second)
	step++
	waitForTOTPStep(t, step)
	page.fill(`input[name="totp_code"]`, totpCode(t, stack.totpSecret, time.Unix(step*30+1, 0)))
	page.clickButton("Confirmer et saisir")

	want := make([]uint32, 0, len(password))
	for _, r := range password {
		want = append(want, uint32(r))
	}
	waitUntil(t, 30*time.Second, "the password, typed by the proxy, at the target", func() bool { return len(typed()) >= before+len(want) })
	if got := typed()[before:]; !slices.Equal(got, want) {
		page.screenshot(dump, "vnc-browser-paste-keys.png")
		t.Fatalf("the target received %v, want %v", got, want)
	}
	page.waitTrue("the sent notice", `document.body.innerText.includes("envoyé chiffré au proxy")`, 10*time.Second)
	if string(page.eval(screenEndedNotice)) == "true" {
		t.Fatal("the screen ended with the paste")
	}
	page.screenshot(dump, "vnc-browser-3-pasted.png")

	// The recording: one marker, its size, and SHA-256(salt‖password); nothing else holds it.
	status, events := stack.api.call(stack.auditorToken, http.MethodGet, "/sessions/"+id+"/recording/video/events?limit=100", nil)
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
		sum := sha256.Sum256(append(salt, password...))
		if err != nil || len(salt) != 16 || e.Source != "operator" || e.PasteBytes != len(password) || e.PasteSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("the paste marker: %+v", e)
		}
	}
	if markers != 1 {
		t.Fatalf("%d paste marker(s), want one", markers)
	}
	if stack.store.holds([]byte(password)) {
		t.Fatal("the object store holds the password in clear")
	}
	if !stack.audit.saw("session.secret_pasted", id) {
		t.Fatal("the typed paste is not audited")
	}
	stack.audit.mu.Lock()
	defer stack.audit.mu.Unlock()
	for _, event := range stack.audit.events {
		if strings.Contains(event, password) {
			t.Fatalf("an audit event holds the password: %s", event)
		}
	}
	if strings.Contains(stack.proxyOut.String(), password) {
		t.Fatal("the screen proxy printed the password")
	}
}

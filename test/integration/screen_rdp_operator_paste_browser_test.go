package integration_test

// ADR-0133 over RDP, against a real Windows: an operator's password typed by the proxy, from the
// page's button. The services of the RDP flow on real processes, the built Admin UI served by the
// Gateway, a headless Chrome. An operator with a second factor signs in, opens the screen of their
// session, clicks Notepad, and types a password through "Saisir un mot de passe…"; Notepad's text is
// then copied back through the clipboard panel, and the page shows it: Windows received the password.
// The recording keeps one paste marker, whose fingerprint is SHA-256(salt‖password).
//
// The password is made up here and worth nothing: the owner allowed a throwaway value to be typed
// into the CI Windows (22 November 2026). Never the target account's password, never a Vault secret.
// Notepad shows it, on purpose: it is the witness; a real operator puts the cursor in a masked field.
//
// In CI only (.github/workflows/windows-rdp.yml): skipped without RDP_WINDOWS (the target),
// TEST_DATABASE_URL (the Video Recorder), the built Admin UI, or a Chrome.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestScreenFlow_RDPOperatorPasteInAHeadlessBrowser(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
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
	certPEM, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatalf("RDP_WINDOWS_CA_FILE: %v", err)
	}
	target := rdpStackTarget{address: os.Getenv("RDP_WINDOWS_ADDRESS"), pin: os.Getenv("RDP_WINDOWS_PIN"), certPEM: certPEM,
		user: os.Getenv("RDP_WINDOWS_USER"), password: os.Getenv("RDP_WINDOWS_PASSWORD"), serverName: os.Getenv("RDP_WINDOWS_SERVER_NAME")}
	dump := os.Getenv("RDP_WINDOWS_DUMP")
	freshWindowsSession(t)
	stack := startRDPScreenStack(t, root, dsn, target, []string{"SCREEN_CLIPBOARD=true"}, []string{"ADMIN_UI_DIR=" + ui})
	// The paste for the step-up user on acc_rdp (ADR-0133); the copy back, Notepad's witness (ADR-0096).
	for _, pol := range []struct{ name, role, resource string }{
		{"rdp-stepup-paste", "rdp-stepup", "secret:paste:account:acc_rdp"},
		{"rdp-paste-clipboard-from", "rdp-ops", "clipboard:from-target:*"},
	} {
		if status := gatewayCreatePolicy(t, stack.gatewayURL, stack.adminToken, pol.name, pol.role, pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}
	status, raw := stack.api.call(stack.stepUpToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0133", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("RDP session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")
	// Made up, worthless, and unlike the account's password.
	password := fmt.Sprintf("Ob-Paste-%d", time.Now().UnixNano()%1_000_000_007)
	if password == target.password {
		t.Fatal("the throwaway password is the target's")
	}

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
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 120*time.Second)
	page.waitTrue("the paste button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Saisir un mot de passe…")`, 15*time.Second)

	// Notepad's text area, as TestScreenFlow_RDPClipboardInAHeadlessBrowser finds it: the centre of
	// the first all-white square of 120 pixels, below the top 30% of the screen.
	page.eval(`document.querySelector("canvas.screen-canvas").scrollIntoView({ block: "start" }), true`)
	const notepad = `(() => { const c = document.querySelector("canvas.screen-canvas"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
		const white = (x, y) => { const i = (y * c.width + x) * 4; return d[i] >= 248 && d[i+1] >= 248 && d[i+2] >= 248; };
		for (let y = Math.floor(c.height * 0.30); y + 120 <= c.height; y += 8) { next: for (let x = 0; x + 120 <= c.width; x += 8) {
			for (let dy = 0; dy < 120; dy += 4) for (let dx = 0; dx < 120; dx += 4) if (!white(x + dx, y + dy)) continue next;
			return [x + 60, y + 60]; } }
		return null; })()`
	var at []float64
	for deadline := time.Now().Add(90 * time.Second); ; {
		_ = json.Unmarshal(page.eval(notepad), &at)
		if len(at) == 2 {
			break
		}
		if time.Now().After(deadline) {
			page.screenshot(dump, "browser-paste-no-notepad.png")
			t.Fatal("no Notepad on the screen after 90 s")
		}
		time.Sleep(time.Second)
	}
	var click []float64
	if err := json.Unmarshal(page.eval(fmt.Sprintf(`(() => { const c = document.querySelector("canvas.screen-canvas");
		c.scrollIntoView({ block: "center" }); const r = c.getBoundingClientRect();
		const x = r.left + %f * r.width / c.width, y = r.top + %f * r.height / c.height;
		return document.elementFromPoint(x, y) === c ? [x, y] : null; })()`, at[0], at[1])), &click); err != nil || len(click) != 2 {
		page.screenshot(dump, "browser-paste-point-hidden.png")
		t.Fatalf("the Notepad point is not on the canvas as the page stands: %v %v", click, err)
	}
	selectAll := cdpKeyA
	if os.Getenv("RDP_WINDOWS_KEYBOARD") == "fr-FR" {
		selectAll = cdpKeyQ // A sits where Q does in AZERTY: the page sends the physical key
	}
	// Notepad focused, its text selected: what the proxy types next replaces it.
	page.clickAt(click[0], click[1])
	time.Sleep(time.Second)
	page.press(cdpControl, selectAll)

	// The page's button, its masked field, a second code.
	page.clickButton("Saisir un mot de passe…")
	page.waitTrue("the masked field", `document.querySelector('#operator-paste-password')?.type === "password"`, 10*time.Second)
	page.fill("#operator-paste-password", password)
	page.clickButton("Continuer")
	page.waitTrue("the paste's second factor", `!!document.querySelector('input[name="totp_code"]')`, 15*time.Second)
	step++
	waitForTOTPStep(t, step)
	page.fill(`input[name="totp_code"]`, totpCode(t, stack.totpSecret, time.Unix(step*30+1, 0)))
	page.clickButton("Confirmer et saisir")
	page.waitTrue("the sent notice", `document.body.innerText.includes("envoyé chiffré au proxy")`, 30*time.Second)
	waitUntil(t, 30*time.Second, "the typed paste, audited by the proxy", func() bool { return stack.audit.saw("session.secret_pasted", id) })
	time.Sleep(2 * time.Second)
	page.screenshot(dump, "browser-paste-1-typed.png")

	// Windows' testimony: Notepad's text, copied back through the clipboard panel, is the password.
	// The modal closed with the paste; the canvas has the keyboard again after a click on Notepad.
	page.clickAt(click[0], click[1])
	time.Sleep(time.Second)
	page.press(cdpControl, selectAll)
	page.press(cdpControl, cdpKeyC)
	quoted, _ := json.Marshal(password)
	page.waitTrue("Notepad's text, copied back and shown by the page",
		fmt.Sprintf(`[...document.querySelectorAll(".screen-clipboard-history li")].some((li) => li.innerText.includes("Copié depuis la cible") && li.querySelector("pre").innerText.trim() === %s)`, quoted), 60*time.Second)
	if string(page.eval(screenEndedNotice)) == "true" {
		page.screenshot(dump, "browser-paste-ended.png")
		t.Fatal("the screen ended with the paste")
	}

	// The recording: one paste marker, its size and SHA-256(salt‖password).
	status, events := stack.api.call(stack.auditorToken, http.MethodGet, "/sessions/"+id+"/recording/video/events?limit=100", nil)
	if status != http.StatusOK || strings.Contains(events, password) {
		t.Fatalf("the recording's events: %d %s", status, events)
	}
	var recorded struct {
		Events []struct {
			EventType   string `json:"eventType"`
			Source      string `json:"source"`
			Protocol    string `json:"protocol"`
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
		if err != nil || len(salt) != 16 || e.Source != "operator" || e.Protocol != "rdp" || e.PasteBytes != len(password) || e.PasteSHA256 != hex.EncodeToString(sum[:]) {
			t.Fatalf("the paste marker: %+v", e)
		}
	}
	if markers != 1 {
		t.Fatalf("%d paste marker(s), want one", markers)
	}
	// The audit has the paste, never its text (the clipboard's copy back is audited by its hash).
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

package integration_test

// ADR-0096, increment 5: the clipboard in a real browser, against a real Windows. The eight services
// of the RDP flow on real processes, SCREEN_CLIPBOARD on at the screen proxy, the operator's role
// holding both clipboard rights, and a headless Chrome that opens the screen through the page and
// uses its panel: a text pasted to the target, pasted in Notepad, copied back from Notepad and shown
// by the page. Then the auditor replays the recording through the public API and finds both
// transfers, and the audit holds both session.clipboard events, without the text.
//
// In CI only (.github/workflows/windows-rdp.yml): skipped without RDP_WINDOWS (the target),
// TEST_DATABASE_URL (the Video Recorder), the built Admin UI, or a Chrome.

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
)

func TestScreenFlow_RDPClipboardInAHeadlessBrowser(t *testing.T) {
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
	stack := startRDPScreenStack(t, root, dsn, target, []string{"SCREEN_CLIPBOARD=true"}, []string{"ADMIN_UI_DIR=" + ui})
	// Both directions for the operator's role (ADR-0096 §1), refused by default.
	for _, pol := range []struct{ name, resource string }{
		{"rdp-clipboard-to", "clipboard:to-target:*"},
		{"rdp-clipboard-from", "clipboard:from-target:*"},
	} {
		if status := gatewayCreatePolicy(t, stack.gatewayURL, stack.adminToken, pol.name, "rdp-ops", pol.resource, "allow", "ignored"); status != http.StatusCreated {
			t.Fatalf("policy %s: %d", pol.name, status)
		}
	}
	status, raw := stack.api.call(stack.operatorToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0096", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("RDP session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")

	page := startHeadlessChrome(t, chrome)
	page.dump = dump
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": stack.gatewayURL + "/ui/"})
	page.waitTrue("the login form", `!!document.querySelector('input[name="username"]')`, 30*time.Second)
	page.fill(`input[name="username"]`, "rdp-operator")
	page.fill(`input[name="password"]`, "op-password-123")
	page.clickButton("Se connecter")
	page.waitTrue("the sections", `[...document.querySelectorAll("nav button")].some((b) => b.innerText.trim() === "Sessions")`, 30*time.Second)
	page.clickButton("Sessions")
	page.waitTrue("the session lookup", `!!document.querySelector('form[aria-label="Chercher une session"] input')`, 15*time.Second)
	page.fill(`form[aria-label="Chercher une session"] input`, id)
	page.clickButton("Afficher")
	page.waitTrue("the screen button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Ouvrir l'écran")`, 15*time.Second)
	page.clickButton("Ouvrir l'écran")
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 120*time.Second)
	// The HELLO offered both directions: the panel says so.
	page.waitTrue("the clipboard panel", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Coller vers la cible…")`, 15*time.Second)

	// Notepad's text, found on the screen as the page shows it: the first all-white square of 120
	// pixels, in the canvas's own pixels, then where that is in the page.
	page.eval(`document.querySelector("canvas.screen-canvas").scrollIntoView({ block: "start" }), true`)
	const notepad = `(() => { const c = document.querySelector("canvas.screen-canvas"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
		const white = (x, y) => { const i = (y * c.width + x) * 4; return d[i] >= 248 && d[i+1] >= 248 && d[i+2] >= 248; };
		for (let y = 0; y + 120 <= c.height; y += 8) { next: for (let x = 0; x + 120 <= c.width; x += 8) {
			for (let dy = 0; dy < 120; dy += 4) for (let dx = 0; dx < 120; dx += 4) if (!white(x + dx, y + dy)) continue next;
			const r = c.getBoundingClientRect(); return [r.left + (x + 60) * r.width / c.width, r.top + (y + 60) * r.height / c.height]; } }
		return null; })()`
	var at []float64
	for deadline := time.Now().Add(90 * time.Second); ; {
		_ = json.Unmarshal(page.eval(notepad), &at)
		if len(at) == 2 {
			break
		}
		if time.Now().After(deadline) {
			page.screenshot(dump, "browser-clipboard-no-notepad.png")
			t.Fatal("no Notepad on the screen after 90 s")
		}
		time.Sleep(time.Second)
	}
	selectAll := cdpKeyA
	if os.Getenv("RDP_WINDOWS_KEYBOARD") == "fr-FR" {
		selectAll = cdpKeyQ // A sits where Q does in AZERTY: the page sends the physical key
	}

	// Paste: the panel's field (the headless browser gives no clipboard), shown, then sent.
	marker := fmt.Sprintf("obbrowser%d", time.Now().UnixNano()%1_000_000_007)
	pasted := "Pasted through the page: " + marker + " é €"
	page.clickButton("Coller vers la cible…")
	page.waitTrue("the paste field", `!!document.querySelector(".screen-clipboard-draft textarea")`, 15*time.Second)
	page.fill(".screen-clipboard-draft textarea", pasted)
	page.clickButton("Envoyer")
	quoted, _ := json.Marshal(pasted)
	page.waitTrue("the pasted text, recorded and shown back",
		fmt.Sprintf(`[...document.querySelectorAll(".screen-clipboard-history li")].some((li) => li.innerText.includes("Collé dans la cible") && li.querySelector("pre").innerText === %s)`, quoted), 30*time.Second)
	// Into Notepad, everything replaced by the pasted text, then copied back.
	page.clickAt(at[0], at[1])
	time.Sleep(time.Second)
	page.press(cdpControl, selectAll)
	page.press(cdpControl, cdpKeyV)
	time.Sleep(2 * time.Second)
	page.screenshot(dump, "browser-clipboard-1-pasted.png")
	page.press(cdpControl, selectAll)
	page.press(cdpControl, cdpKeyC)
	page.waitTrue("the text Notepad copied, shown by the page",
		fmt.Sprintf(`[...document.querySelectorAll(".screen-clipboard-history li")].some((li) => li.innerText.includes("Copié depuis la cible") && li.querySelector("pre").innerText.includes(%q))`, marker), 60*time.Second)
	page.eval(`document.querySelector(".screen-clipboard").scrollIntoView({ block: "start" }), true`)
	page.screenshot(dump, "browser-clipboard-2-copied.png")
	// Copy: the page writes it to the operator's clipboard on the click. A headless browser may
	// refuse the write; the page says which, and that is what is logged.
	page.clickButton("Copier le texte de la cible")
	page.waitTrue("the copy's outcome", `/copié dans votre presse-papiers|refusé l'écriture/.test(document.querySelector(".screen-clipboard").innerText)`, 15*time.Second)
	t.Logf("the copy button: %s", page.eval(`[...document.querySelectorAll(".screen-clipboard [role]")].map((e) => e.innerText).join(" | ")`))

	// The session ends; the auditor replays it and finds both transfers in the recording.
	status, raw = stack.api.call(stack.operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	if status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, raw)
	}
	var transfers []screenstream.Message
	waitUntil(t, 30*time.Second, "the sealed recording", func() bool {
		transfers = nil
		complete := false
		for firstSequence := uint64(1); ; {
			status, raw := stack.api.call(stack.auditorToken, http.MethodGet, fmt.Sprintf("/sessions/%s/recording/video/segments/%d", id, firstSequence), nil)
			if status == http.StatusNotFound && firstSequence > 1 {
				return complete
			}
			if status != http.StatusOK {
				return false
			}
			var segment struct {
				LastSequence uint64 `json:"lastSequence"`
				Complete     bool   `json:"complete"`
				Frames       []struct {
					FrameData string `json:"frameData"`
					Codec     string `json:"codec"`
				} `json:"frames"`
			}
			if json.Unmarshal([]byte(raw), &segment) != nil || segment.LastSequence < firstSequence {
				return false
			}
			for _, frame := range segment.Frames {
				if frame.Codec != "clipboard-text-v1" {
					continue
				}
				data, err := base64.StdEncoding.DecodeString(frame.FrameData)
				if err != nil {
					return false
				}
				message, err := screenstream.Decode(data)
				if err != nil {
					return false
				}
				transfers = append(transfers, message)
			}
			complete = segment.Complete
			firstSequence = segment.LastSequence + 1
		}
	})
	var to, from bool
	for _, m := range transfers {
		to = to || (m.Direction == screenstream.ClipboardToTarget && m.ClipboardText == pasted)
		from = from || (m.Direction == screenstream.ClipboardFromTarget && strings.Contains(m.ClipboardText, marker))
	}
	if !to || !from {
		t.Fatalf("the replay holds %d transfer(s): pasted %v, copied %v", len(transfers), to, from)
	}
	t.Logf("replayed through the public API: %d clipboard transfer(s), the paste and the copy among them", len(transfers))
	// The audit holds both, with their direction and hash, never the text.
	waitUntil(t, 10*time.Second, "both session.clipboard events", func() bool {
		stack.audit.mu.Lock()
		defer stack.audit.mu.Unlock()
		var sawTo, sawFrom bool
		for _, event := range stack.audit.events {
			if !strings.Contains(event, `"session.clipboard"`) || !strings.Contains(event, id) {
				continue
			}
			if strings.Contains(event, marker) {
				t.Fatalf("an audit event holds the text: %s", event)
			}
			sawTo = sawTo || strings.Contains(event, `"to-target"`)
			sawFrom = sawFrom || strings.Contains(event, `"from-target"`)
		}
		return sawTo && sawFrom
	})
}

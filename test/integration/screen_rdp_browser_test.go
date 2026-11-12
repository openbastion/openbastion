package integration_test

// ADR-0095, increment 5: the resize in a real browser, against a real Windows. The eight services
// of the RDP flow on real processes, SCREEN_RESIZE on at the screen proxy, the Admin UI served by
// the Gateway (ADMIN_UI_DIR), and a headless Chrome that logs in, opens the screen of an RDP session
// through the page's own buttons, and is resized: the remote desktop must follow the room the page
// has, at each size. Screenshots go to RDP_WINDOWS_DUMP for a person to judge.
//
// In CI only (.github/workflows/windows-rdp.yml): skipped without RDP_WINDOWS (the target),
// TEST_DATABASE_URL (the Video Recorder), the built Admin UI, or a Chrome.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestScreenFlow_RDPResizeInAHeadlessBrowser(t *testing.T) {
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
	stack := startRDPScreenStack(t, root, dsn, target, []string{"SCREEN_RESIZE=true"}, []string{"ADMIN_UI_DIR=" + ui})
	status, raw := stack.api.call(stack.operatorToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0095", "durationMinutes": 10})
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
	page.waitTrue("the sections", `[...document.querySelectorAll("nav button")].some((b) => b.textContent.trim() === "Sessions")`, 30*time.Second)
	page.clickButton("Sessions")
	page.waitTrue("the session lookup", `!!document.querySelector('form[aria-label="Chercher une session"] input')`, 15*time.Second)
	page.fill(`form[aria-label="Chercher une session"] input`, id)
	page.clickButton("Afficher")
	page.waitTrue("the screen button", `[...document.querySelectorAll("button")].some((b) => b.textContent.trim() === "Ouvrir l'écran")`, 15*time.Second)
	page.clickButton("Ouvrir l'écran")
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 120*time.Second)

	// The size the page asks for, as ScreenViewer measures it: the width of its area, the height of
	// the window below it, less what stands above the canvas; within the bounds, the width even.
	const wanted = `(() => { const a = document.querySelector(".screen"); const r = a.getBoundingClientRect();
		const w = Math.min(Math.max(Math.floor(a.clientWidth), 640), 2560); const h = Math.min(Math.max(Math.floor(window.innerHeight - r.top - 112), 480), 1600);
		return [w - (w % 2), h]; })()`
	const shown = `(() => { const c = document.querySelector("canvas.screen-canvas"); return [c.width, c.height]; })()`
	follow := func(step string) [2]int {
		var want, got [2]int
		for deadline := time.Now().Add(60 * time.Second); ; {
			_ = json.Unmarshal(page.eval(wanted), &want)
			_ = json.Unmarshal(page.eval(shown), &got)
			if want == got {
				t.Logf("%s: the page asked for %dx%d, and shows Windows' desktop at that size", step, want[0], want[1])
				page.screenshot(dump, fmt.Sprintf("browser-resize-%s.png", step))
				return got
			}
			if time.Now().After(deadline) {
				page.screenshot(dump, fmt.Sprintf("browser-resize-%s-failed.png", step))
				t.Fatalf("%s: the page asks for %dx%d, the screen is %dx%d after 60 s", step, want[0], want[1], got[0], got[1])
			}
			time.Sleep(500 * time.Millisecond)
		}
	}
	first := follow("opened")
	page.viewport(1100, 800)
	second := follow("smaller")
	page.viewport(1700, 1100)
	third := follow("larger")
	if first == second || second == third {
		t.Fatalf("the sizes did not change: %v, %v, %v", first, second, third)
	}
	// The session goes on: the page says it is live, not ended.
	if string(page.eval(`!!document.querySelector('.notice.error[role="alert"]')`)) == "true" {
		page.screenshot(dump, "browser-resize-ended.png")
		t.Fatal("the screen ended during the resizes")
	}
}

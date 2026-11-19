package integration_test

// The checks the Windows browser tests make of the Admin UI, proved here without Windows: the
// navigation, the session lookup and the "Ouvrir l'écran" button they go through (cdpPage.signIn,
// showSession, openScreen), and screenEndedNotice, the one that says a screen ended. The API is
// stubbed at the browser boundary, as in TestAdminUI_SecretInjectionStepUpInAHeadlessBrowser; the
// screen's WebSocket is refused, so the viewer must show its end. The counter-proof of the
// selector: false while the viewer is connecting, true once it has ended. A selector that matches
// nothing (".notice.error" after the move to @openbastion/ui) fails here instead of passing silently
// on Windows.

import (
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func TestAdminUI_ScreenEndIsSeenInAHeadlessBrowser(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		t.Skip("CHROME is not set; run from the dedicated Admin UI browser CI job")
	}
	root := repoRoot(t)
	token := browserTestToken(t)
	const id = "browser-screen-session"
	release := make(chan struct{})
	var upgrades atomic.Int32
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/ldap":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/oidc":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/login":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"accessToken": token})
		case r.Header.Get("Authorization") != "Bearer "+token && r.URL.Path != "/sessions/"+id+"/screen":
			http.Error(w, "missing bearer", http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"items": []any{}, "page": 1, "pageSize": 50, "totalItems": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/"+id:
			writeBrowserJSON(w, http.StatusOK, map[string]any{
				"id": id, "status": "active", "protocol": "rdp",
				"requestedBy": "browser-operator", "privilegedAccountId": "acc-browser-rdp",
				"justification": "Chromium screen end", "breakGlass": false,
				"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/"+id+"/connect":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"protocol": "rdp", "attach": "/sessions/" + id + "/screen"})
		case r.URL.Path == "/sessions/"+id+"/screen":
			// The upgrade is held, so the viewer is seen connecting, then refused: the screen ends.
			upgrades.Add(1)
			select {
			case <-release:
			case <-r.Context().Done():
				return
			case <-time.After(20 * time.Second):
			}
			http.Error(w, "screen refused", http.StatusGone)
		default:
			http.Error(w, "unexpected API route", http.StatusNotFound)
		}
	}))
	defer api.Close()

	uiURL := startAdminUIPreview(t, root, api.URL)
	page := startHeadlessChrome(t, chrome)
	page.dump = os.Getenv("ADMIN_UI_BROWSER_DUMP")
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": uiURL + "/"})
	page.signIn("browser-operator", "browser-password")
	page.showSession(id)
	page.openScreen()

	waitUntil(t, 15*time.Second, "the screen's upgrade", func() bool { return upgrades.Load() > 0 })
	page.waitTrue("the viewer, connecting", `!!document.querySelector(".screen")`, 10*time.Second)
	if got := string(page.eval(screenEndedNotice)); got != "false" {
		page.screenshot(page.dump, "screen-end-early.png")
		t.Fatalf("screenEndedNotice while the screen connects: %s", got)
	}
	close(release)
	page.waitTrue("the screen's end, as screenEndedNotice sees it", screenEndedNotice, 15*time.Second)
	page.waitTrue("the reconnect button", `[...document.querySelectorAll(".screen button")].some((b) => b.innerText.trim() === "Se reconnecter")`, 5*time.Second)
}

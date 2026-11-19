package integration_test

// ADR-0097: exercise the real Admin UI in Chromium. The API boundary is deterministic and stubbed;
// real-process integration tests separately prove the Broker/Vault/proxy/Recorder/Audit path.
import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"testing"
	"time"
)

func TestAdminUI_SecretInjectionStepUpInAHeadlessBrowser(t *testing.T) {
	// This test owns a Vite/npm preview and is prepared by the dedicated browser CI job.
	// Do not auto-discover a runner-wide Chrome in other integration jobs (notably PostgreSQL),
	// where the UI dependencies are intentionally not installed.
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		t.Skip("CHROME is not set; run from the dedicated Admin UI browser CI job")
	}
	root := repoRoot(t)
	token := browserTestToken(t)

	injectionCalls := make(chan []byte, 1)
	releaseInjection := make(chan struct{})
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/ldap":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/oidc":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/login":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"accessToken": token})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			if r.URL.Query().Get("status") != "pending_approval" || r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "unexpected sessions request", http.StatusUnauthorized)
				return
			}
			writeBrowserJSON(w, http.StatusOK, map[string]any{"items": []any{}, "page": 1, "pageSize": 50, "totalItems": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/browser-e2e-session":
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			writeBrowserJSON(w, http.StatusOK, map[string]any{
				"id": "browser-e2e-session", "status": "active", "protocol": "vnc",
				"requestedBy": "browser-operator", "privilegedAccountId": "acc-browser-e2e",
				"justification": "Chromium browser E2E", "breakGlass": false,
				"expiresAt": time.Now().Add(5 * time.Minute).UTC().Format(time.RFC3339),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/browser-e2e-session/secret-injection-step-up":
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			body, _ := io.ReadAll(http.MaxBytesReader(w, r.Body, 1))
			if len(body) != 0 {
				http.Error(w, "step-up body must be empty", http.StatusBadRequest)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			writeBrowserJSON(w, http.StatusOK, map[string]any{
				"challenge": "browser-e2e-challenge", "expires_in": 120, "factors": []string{"totp"},
			})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/browser-e2e-session/secret-injection":
			if r.Header.Get("Authorization") != "Bearer "+token {
				http.Error(w, "missing bearer", http.StatusUnauthorized)
				return
			}
			body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 8<<10))
			if err != nil {
				http.Error(w, "invalid body", http.StatusBadRequest)
				return
			}
			injectionCalls <- body
			select {
			case <-releaseInjection:
				w.Header().Set("Cache-Control", "no-store")
				w.WriteHeader(http.StatusNoContent)
			case <-r.Context().Done():
			case <-time.After(15 * time.Second):
				http.Error(w, "test timed out", http.StatusGatewayTimeout)
			}
		default:
			http.Error(w, "unexpected API route", http.StatusNotFound)
		}
	}))
	defer api.Close()

	uiURL := startAdminUIPreview(t, root, api.URL)
	page := startHeadlessChrome(t, chrome)
	page.dump = os.Getenv("ADMIN_UI_BROWSER_DUMP")
	page.viewport(1440, 1000)
	var navigation struct {
		ErrorText string `json:"errorText"`
	}
	if err := json.Unmarshal(page.call("Page.navigate", map[string]any{"url": uiURL + "/"}), &navigation); err != nil {
		t.Fatalf("decode browser navigation result: %v", err)
	}
	if navigation.ErrorText != "" {
		t.Fatalf("navigate to Admin UI at %s: %s", uiURL, navigation.ErrorText)
	}
	page.waitTrue("login form", "!!document.querySelector('input[name=\"username\"]')", 30*time.Second)
	page.fill("input[name=\"username\"]", "browser-operator")
	page.fill("input[name=\"password\"]", "browser-password")
	page.clickButton("Se connecter")
	page.waitTrue("authenticated navigation", "[...document.querySelectorAll(\"nav button\")].some((b) => b.innerText.trim() === \"Sessions\")", 20*time.Second)

	// The token is held by the in-memory API client, not persisted by the page.
	var storage string
	if err := json.Unmarshal(page.eval("JSON.stringify({local: localStorage.length, session: sessionStorage.length, cookiePresent: document.cookie.length > 0})"), &storage); err != nil {
		t.Fatal(err)
	}
	if storage != "{\"local\":0,\"session\":0,\"cookiePresent\":false}" {
		t.Fatalf("browser persisted authentication state: %s", storage)
	}

	page.clickButton("Sessions")
	page.waitTrue("session lookup", "!!document.querySelector(\"#session-lookup\")", 15*time.Second)
	page.fill("#session-lookup", "browser-e2e-session")
	page.clickButton("Afficher")
	page.waitTrue("Vault injection action", "[...document.querySelectorAll(\"button\")].some((b) => b.innerText.trim() === \"Saisir le secret Vault\")", 15*time.Second)
	page.clickButton("Saisir le secret Vault")
	page.waitTrue("operator warning", "document.body.innerText.includes(\"placez le focus sur le champ de mot de passe masqué\")", 10*time.Second)
	page.clickButton("Continuer vers la confirmation MFA")
	page.waitTrue("TOTP challenge", "!!document.querySelector('input[name=\"totp_code\"]')", 10*time.Second)
	page.fill("input[name=\"totp_code\"]", "123456")
	page.clickButton("Confirmer et saisir")

	var body []byte
	select {
	case body = <-injectionCalls:
	case <-time.After(15 * time.Second):
		page.screenshot(page.dump, "secret-injection-browser-timeout.png")
		t.Fatal("the browser did not submit the MFA proof")
	}

	// The response is held open: the code must already be gone from the live DOM before the
	// browser receives a success response.
	if got := string(page.eval("document.querySelector('input[name=\"totp_code\"]')?.value ?? \"\"")); got != "\"\"" {
		t.Fatalf("TOTP remains in the DOM while the request is in flight: %s", got)
	}
	var proof map[string]any
	if err := json.Unmarshal(body, &proof); err != nil {
		t.Fatalf("decode browser proof: %v", err)
	}
	if len(proof) != 3 || proof["challenge"] != "browser-e2e-challenge" || proof["factor"] != "totp" || proof["totp_code"] != "123456" {
		t.Fatalf("browser sent unexpected injection proof fields: %#v", proof)
	}
	for _, forbidden := range []string{"account_id", "accountId", "credential", "password", "secret", "grant", "vault_scope_token", "scope"} {
		if _, ok := proof[forbidden]; ok {
			t.Fatalf("browser proof unexpectedly contains %q", forbidden)
		}
	}
	close(releaseInjection)
	page.waitTrue("injection success notice", "document.body.innerText.includes(\"Le proxy a confirmé la saisie du secret Vault dans la session.\")", 15*time.Second)

	origin, _ := json.Marshal(uiURL)
	if string(page.eval("location.origin === "+string(origin))) != "true" {
		t.Fatalf("Admin UI navigated away from its origin: %s", page.eval("location.origin"))
	}
}

func writeBrowserJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func browserTestToken(t *testing.T) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"sub": "user-browser-e2e", "username": "browser-operator",
		"roles": []string{"platform-admin"}, "exp": time.Now().Add(time.Hour).Unix(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return "e30." + base64.RawURLEncoding.EncodeToString(payload) + ".test-signature"
}

func startAdminUIPreview(t *testing.T, root, gatewayURL string) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()

	uiDir := filepath.Join(root, "web", "admin-ui")
	cmd := exec.Command("npm", "run", "dev", "--", "--host", "127.0.0.1", "--port", strconv.Itoa(port), "--strictPort")
	cmd.Dir = uiDir
	cmd.Env = append(os.Environ(), "BASE44_PREVIEW_MODE=1", "BASE44_GATEWAY_URL="+gatewayURL)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start Vite: %v", err)
	}
	t.Cleanup(func() {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
		_ = cmd.Wait()
	})
	url := fmt.Sprintf("http://127.0.0.1:%d", port)
	client := &http.Client{Timeout: 2 * time.Second}
	for deadline := time.Now().Add(30 * time.Second); ; {
		resp, err := client.Get(url + "/")
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return url
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Vite did not become ready at %s", url)
		}
		time.Sleep(150 * time.Millisecond)
	}
}

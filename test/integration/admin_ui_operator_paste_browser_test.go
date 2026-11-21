package integration_test

// ADR-0133 in a real browser: the Admin UI in Chromium encrypts an operator's password for the
// screen proxy, and the proxy's own code opens it. The API is stubbed at the browser boundary, as in
// TestAdminUI_SecretInjectionStepUpInAHeadlessBrowser; the screen's WebSocket is served here with a
// key drawn by pkg/proxycore.NewPasteKey and opened by (*PasteKey).Open, the very code the screen
// proxy runs. TestScreenFlow_VNCFromThePublicAPIToTheTargetAndBack_AcrossRealProcesses proves the rest
// on real processes: the Gateway and the proxy pass the message on, the proxy types it, the recording
// keeps only the salted fingerprint.
//
// The claims: the page sends the factor's proof and nothing else to the API; it sends one InputPaste
// on the screen, bound to this session and to the Broker's token; the proxy's code opens it to the
// very password typed; no API request and no other screen message carries the password.

import (
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

func TestAdminUI_OperatorPasteIsOpenedByTheProxysCodeInAHeadlessBrowser(t *testing.T) {
	chrome := os.Getenv("CHROME")
	if chrome == "" {
		t.Skip("CHROME is not set; run from the dedicated Admin UI browser CI job")
	}
	root := repoRoot(t)
	token := browserTestToken(t)
	const id = "browser-paste-session"
	const password = "Browser-Paste-9é"
	pasteToken := strings.Repeat("5a", 32)
	key, err := proxycore.NewPasteKey()
	if err != nil {
		t.Fatal(err)
	}

	var mu sync.Mutex
	var apiBodies []string
	pastes := make(chan screenstream.PasteInput, 4)
	others := make(chan []byte, 64)
	api := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/sessions/"+id+"/screen" {
			body, _ := io.ReadAll(r.Body)
			mu.Lock()
			apiBodies = append(apiBodies, r.Method+" "+r.URL.Path+" "+string(body))
			mu.Unlock()
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/auth/ldap":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/oidc":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"enabled": false, "providers": []any{}})
		case r.Method == http.MethodPost && r.URL.Path == "/auth/login":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"accessToken": token})
		case r.Method == http.MethodGet && r.URL.Path == "/auth/me/capabilities":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"capabilities": map[string]bool{"secrets.paste": true, "sessions.create": true}})
		case r.URL.Path == "/sessions/"+id+"/screen":
			// The proxy's side: a HELLO with the key, then what the page sends.
			conn, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"openbastion.screen.v1"}, InsecureSkipVerify: true})
			if err != nil {
				return
			}
			defer conn.CloseNow()
			hello, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeHello, Timestamp: time.Now().UTC(),
				Protocol: screenstream.ProtocolVNC, ExpiresAt: time.Now().Add(10 * time.Minute), SessionID: id, PasteKey: key.Public()})
			if err != nil {
				t.Errorf("HELLO: %v", err)
				return
			}
			if err := conn.Write(r.Context(), websocket.MessageBinary, hello); err != nil {
				return
			}
			for {
				_, data, err := conn.Read(r.Context())
				if err != nil {
					return
				}
				if screenstream.IsPasteInput(data) {
					in, err := screenstream.DecodePasteInput(data)
					if err != nil {
						t.Errorf("the page's InputPaste does not decode: %v", err)
						return
					}
					pastes <- in
					continue
				}
				select {
				case others <- data:
				default:
				}
			}
		case r.Header.Get("Authorization") != "Bearer "+token:
			http.Error(w, "missing bearer", http.StatusUnauthorized)
		case r.Method == http.MethodGet && r.URL.Path == "/sessions":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"items": []any{}, "page": 1, "pageSize": 50, "totalItems": 0})
		case r.Method == http.MethodGet && r.URL.Path == "/sessions/"+id:
			writeBrowserJSON(w, http.StatusOK, map[string]any{
				"id": id, "status": "active", "protocol": "vnc",
				"requestedBy": "user-browser-e2e", "privilegedAccountId": "acc-browser-vnc",
				"justification": "Chromium operator paste", "breakGlass": false,
				"expiresAt": time.Now().Add(10 * time.Minute).UTC().Format(time.RFC3339),
			})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/"+id+"/connect":
			writeBrowserJSON(w, http.StatusOK, map[string]any{"protocol": "vnc", "attach": "/sessions/" + id + "/screen"})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/"+id+"/secret-paste-step-up":
			w.Header().Set("Cache-Control", "no-store")
			writeBrowserJSON(w, http.StatusOK, map[string]any{"challenge": "opaque-paste-challenge", "expires_in": 120, "factors": []string{"totp"}})
		case r.Method == http.MethodPost && r.URL.Path == "/sessions/"+id+"/secret-paste":
			w.Header().Set("Cache-Control", "no-store")
			writeBrowserJSON(w, http.StatusOK, map[string]any{"pasteToken": pasteToken, "expiresInSeconds": 60})
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

	// The HELLO offered the key: the button is there; the password goes in a masked field.
	page.waitTrue("the paste button", `[...document.querySelectorAll("button")].some((b) => b.innerText.trim() === "Saisir un mot de passe…")`, 20*time.Second)
	page.clickButton("Saisir un mot de passe…")
	page.waitTrue("the masked field", `!!document.querySelector('#operator-paste-password') && document.querySelector('#operator-paste-password').type === "password"`, 10*time.Second)
	page.fill("#operator-paste-password", password)
	page.clickButton("Continuer")
	page.waitTrue("the TOTP challenge", `!!document.querySelector('input[name="totp_code"]')`, 10*time.Second)
	page.fill(`input[name="totp_code"]`, "123456")
	page.clickButton("Confirmer et saisir")

	var in screenstream.PasteInput
	select {
	case in = <-pastes:
	case <-time.After(20 * time.Second):
		page.screenshot(page.dump, "operator-paste-browser-timeout.png")
		t.Fatal("no InputPaste reached the screen after the factor")
	}
	if got := hex.EncodeToString(in.Token[:]); got != pasteToken {
		t.Fatalf("the paste's token %s, want the Broker's %s", got, pasteToken)
	}
	// The proxy's code opens what the page encrypted, for this session and this protocol only.
	plain, err := key.Open(id, "vnc", in)
	if err != nil {
		t.Fatalf("the proxy's code does not open the page's paste: %v", err)
	}
	if string(plain) != password {
		t.Fatalf("opened %q, want the password typed", plain)
	}
	if _, err := key.Open(id+"-other", "vnc", in); err == nil {
		t.Fatal("the page's paste opens for another session")
	}
	if _, err := key.Open(id, "rdp", in); err == nil {
		t.Fatal("the page's paste opens for another protocol")
	}
	page.waitTrue("the sent notice", `document.body.innerText.includes("envoyé chiffré au proxy")`, 10*time.Second)
	if string(page.eval(`!!document.querySelector('#operator-paste-password')`)) != "false" {
		t.Fatal("the password field is still open after the paste")
	}

	// The password went nowhere else: not to the API, not in another screen message.
	mu.Lock()
	sent := strings.Join(apiBodies, "\n")
	mu.Unlock()
	if strings.Contains(sent, password) {
		t.Fatalf("an API request carried the password:\n%s", sent)
	}
	var proof map[string]any
	for _, line := range strings.Split(sent, "\n") {
		if rest, ok := strings.CutPrefix(line, "POST /sessions/"+id+"/secret-paste "); ok {
			if err := json.Unmarshal([]byte(rest), &proof); err != nil {
				t.Fatalf("the paste proof: %v %q", err, rest)
			}
		}
	}
	if len(proof) != 3 || proof["challenge"] != "opaque-paste-challenge" || proof["factor"] != "totp" || proof["totp_code"] != "123456" {
		t.Fatalf("the paste proof sent %v, want the factor's proof only", proof)
	}
	for drained := false; !drained; {
		select {
		case data := <-others:
			if strings.Contains(string(data), password) {
				t.Fatal("a screen message carried the password in clear")
			}
		default:
			drained = true
		}
	}
	select {
	case extra := <-pastes:
		t.Fatalf("a second InputPaste was sent: %d bytes", len(extra.Ciphertext))
	case <-time.After(500 * time.Millisecond):
	}
}

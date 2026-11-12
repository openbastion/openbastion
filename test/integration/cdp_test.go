package integration_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

// A headless Chrome, driven by the Chrome DevTools Protocol over its WebSocket (ADR-0095,
// increment 5): what a real browser does with the Admin UI, with no dependency but the WebSocket
// client the module already has. The browser is the one the CI runner has (CHROME, or the first of
// google-chrome, chromium, chromium-browser on PATH).

// findChrome is the browser to run, or "" when there is none.
func findChrome() string {
	if path := os.Getenv("CHROME"); path != "" {
		return path
	}
	for _, name := range []string{"google-chrome", "chromium", "chromium-browser"} {
		if path, err := exec.LookPath(name); err == nil {
			return path
		}
	}
	return ""
}

type cdpPage struct {
	t    *testing.T
	conn *websocket.Conn
	next int
}

// startHeadlessChrome starts chrome with nothing of the user's, and returns its first page.
func startHeadlessChrome(t *testing.T, chrome string) *cdpPage {
	t.Helper()
	profile := t.TempDir()
	cmd := exec.Command(chrome, "--headless=new", "--no-first-run", "--no-default-browser-check", "--disable-gpu",
		"--disable-extensions", "--remote-debugging-port=0", "--user-data-dir="+profile, "--window-size=1400,1000", "about:blank")
	if os.Getuid() == 0 {
		cmd.Args = append(cmd.Args, "--no-sandbox")
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("starting %s: %v", chrome, err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	// Chrome writes the port it took, then the browser's path, in its profile.
	var port string
	for deadline := time.Now().Add(30 * time.Second); port == ""; {
		if raw, err := os.ReadFile(filepath.Join(profile, "DevToolsActivePort")); err == nil {
			port = strings.TrimSpace(strings.Split(string(raw), "\n")[0])
		}
		if port == "" && time.Now().After(deadline) {
			t.Fatal("Chrome did not open its DevTools port")
		}
		time.Sleep(100 * time.Millisecond)
	}
	var targets []struct{ Type, WebSocketDebuggerURL string }
	for deadline := time.Now().Add(15 * time.Second); ; {
		resp, err := http.Get("http://127.0.0.1:" + port + "/json/list")
		if err == nil {
			err = json.NewDecoder(resp.Body).Decode(&targets)
			_ = resp.Body.Close()
		}
		for _, target := range targets {
			if target.Type == "page" {
				conn, _, err := websocket.Dial(context.Background(), target.WebSocketDebuggerURL, nil)
				if err != nil {
					t.Fatalf("DevTools: %v", err)
				}
				conn.SetReadLimit(64 << 20) // screenshots
				t.Cleanup(func() { _ = conn.Close(websocket.StatusNormalClosure, "") })
				return &cdpPage{t: t, conn: conn}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no page in Chrome: %v", err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// call sends one command and returns its result; the events in between are not read for.
func (p *cdpPage) call(method string, params any) json.RawMessage {
	p.t.Helper()
	p.next++
	id := p.next
	raw, err := json.Marshal(map[string]any{"id": id, "method": method, "params": params})
	if err != nil {
		p.t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := p.conn.Write(ctx, websocket.MessageText, raw); err != nil {
		p.t.Fatalf("%s: %v", method, err)
	}
	for {
		_, data, err := p.conn.Read(ctx)
		if err != nil {
			p.t.Fatalf("%s: %v", method, err)
		}
		var answer struct {
			ID     int             `json:"id"`
			Result json.RawMessage `json:"result"`
			Error  *struct {
				Message string `json:"message"`
			} `json:"error"`
		}
		if json.Unmarshal(data, &answer) != nil || answer.ID != id {
			continue
		}
		if answer.Error != nil {
			p.t.Fatalf("%s: %s", method, answer.Error.Message)
		}
		return answer.Result
	}
}

// eval runs expression in the page, awaits it if it is a promise, and returns its value as JSON.
func (p *cdpPage) eval(expression string) json.RawMessage {
	p.t.Helper()
	var result struct {
		Result struct {
			Value json.RawMessage `json:"value"`
		} `json:"result"`
		ExceptionDetails *struct {
			Text      string `json:"text"`
			Exception struct {
				Description string `json:"description"`
			} `json:"exception"`
		} `json:"exceptionDetails"`
	}
	raw := p.call("Runtime.evaluate", map[string]any{"expression": expression, "awaitPromise": true, "returnByValue": true})
	if err := json.Unmarshal(raw, &result); err != nil {
		p.t.Fatal(err)
	}
	if result.ExceptionDetails != nil {
		p.t.Fatalf("in the page: %s %s", result.ExceptionDetails.Text, result.ExceptionDetails.Exception.Description)
	}
	return result.Result.Value
}

// waitTrue waits for expression to be true in the page.
func (p *cdpPage) waitTrue(what, expression string, limit time.Duration) {
	p.t.Helper()
	for deadline := time.Now().Add(limit); ; {
		if string(p.eval(expression)) == "true" {
			return
		}
		if time.Now().After(deadline) {
			p.t.Fatalf("waited %s for %s", limit, what)
		}
		time.Sleep(250 * time.Millisecond)
	}
}

// fill sets a React-controlled input as a person typing does: through the native setter, then an
// input event, which React listens to.
func (p *cdpPage) fill(selector, value string) {
	p.t.Helper()
	sel, _ := json.Marshal(selector)
	val, _ := json.Marshal(value)
	p.eval(fmt.Sprintf(`(() => { const el = document.querySelector(%s); if (!el) throw new Error("no " + %s);
		Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set.call(el, %s);
		el.dispatchEvent(new Event("input", { bubbles: true })); return true; })()`, sel, sel, val))
}

// clickButton clicks the button whose text is text.
func (p *cdpPage) clickButton(text string) {
	p.t.Helper()
	label, _ := json.Marshal(text)
	p.eval(fmt.Sprintf(`(() => { const b = [...document.querySelectorAll("button")].find((b) => b.textContent.trim() === %s);
		if (!b) throw new Error("no button " + %s); b.click(); return true; })()`, label, label))
}

// viewport sets the page's size, as a window resized to it.
func (p *cdpPage) viewport(width, height int) {
	p.t.Helper()
	p.call("Emulation.setDeviceMetricsOverride", map[string]any{"width": width, "height": height, "deviceScaleFactor": 1, "mobile": false})
}

// screenshot writes the page as a PNG in dir, when dir is set.
func (p *cdpPage) screenshot(dir, name string) {
	p.t.Helper()
	if dir == "" {
		return
	}
	var shot struct {
		Data string `json:"data"`
	}
	if err := json.Unmarshal(p.call("Page.captureScreenshot", map[string]any{"format": "png"}), &shot); err != nil {
		p.t.Fatal(err)
	}
	png, err := base64.StdEncoding.DecodeString(shot.Data)
	if err != nil {
		p.t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, name), png, 0o644); err != nil {
		p.t.Fatal(err)
	}
}

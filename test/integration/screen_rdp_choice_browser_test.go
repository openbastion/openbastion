package integration_test

// ADR-0132, increment 4: the operator's screen choice, against a real Windows, in a real browser.
// The account's administrator allows the bitmap channel only; a choice outside that is refused
// before anything opens. The operator then chooses bitmap and 16 bits in the page, opens the screen
// and types into Notepad. The proxy says what was asked and what the target chose, the graphics
// pipeline is not offered, and the auditor replays the recording through the public API.
// Screenshots go to RDP_WINDOWS_DUMP (browser-choice-*.png).
//
// In CI only (.github/workflows/windows-rdp.yml): skipped without RDP_WINDOWS (the target),
// TEST_DATABASE_URL (the Video Recorder), the built Admin UI, or a Chrome.

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"image/png"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestScreenFlow_RDPScreenChoiceInAHeadlessBrowser(t *testing.T) {
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
	// The pipeline is on at the proxy (the default): it is the account's profile that keeps it out.
	stack := startRDPScreenStack(t, root, dsn, target, []string{"SCREEN_RDPGFX=true"}, []string{"ADMIN_UI_DIR=" + ui})

	// The account's administrator allows the bitmap channel only, at either depth.
	status, raw := stack.api.call(stack.adminToken, http.MethodPut, "/vault/accounts/acc_rdp/screen-profile", map[string]any{
		"screenProfile": map[string]any{"channels": []string{"bitmap"}, "defaultChannel": "bitmap", "colorDepths": []int{16, 32}, "defaultColorDepth": 32},
	})
	if status != http.StatusOK {
		t.Fatalf("the account's screen profile: %d %s", status, raw)
	}
	status, raw = stack.api.call(stack.operatorToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0132", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("RDP session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")
	// Outside the profile: refused before any scope, and the session stays as it was.
	if status, raw := stack.api.call(stack.operatorToken, http.MethodPost, "/sessions/"+id+"/connect", map[string]any{"screen": map[string]any{"channel": "graphics"}}); status != http.StatusForbidden {
		t.Fatalf("the graphics pipeline, outside the account's profile: %d %s, want 403", status, raw)
	}

	page := startHeadlessChrome(t, chrome)
	page.dump = dump
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": stack.gatewayURL + "/ui/"})
	page.signIn("rdp-operator", "op-password-123")
	page.showSession(id)
	page.waitTrue("the screen choice", fmt.Sprintf(`!!document.querySelector("#screen-choice-channel-%s")`, id), 15*time.Second)
	page.choose("#screen-choice-channel-"+id, "bitmap")
	page.choose("#screen-choice-depth-"+id, "16")
	page.screenshot(dump, "browser-choice-0-chosen.png")
	page.openScreen()
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 120*time.Second)
	page.eval(`document.querySelector("canvas.screen-canvas").scrollIntoView({ block: "center" }), true`)
	page.screenshot(dump, "browser-choice-1-opened.png")

	// The bitmap path draws what changes: keys typed into Notepad change the canvas.
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
			page.screenshot(dump, "browser-choice-no-notepad.png")
			t.Fatal("no Notepad on the screen after 90 s")
		}
		time.Sleep(time.Second)
	}
	var click []float64
	if err := json.Unmarshal(page.eval(fmt.Sprintf(`(() => { const c = document.querySelector("canvas.screen-canvas");
		c.scrollIntoView({ block: "center" }); const r = c.getBoundingClientRect();
		const x = r.left + %f * r.width / c.width, y = r.top + %f * r.height / c.height;
		return document.elementFromPoint(x, y) === c ? [x, y] : null; })()`, at[0], at[1])), &click); err != nil || len(click) != 2 {
		t.Fatalf("the Notepad point is not on the canvas: %v %v", click, err)
	}
	page.clickAt(click[0], click[1])
	time.Sleep(time.Second)
	const canvasHash = `(() => { const c = document.querySelector("canvas.screen-canvas"); const d = c.getContext("2d").getImageData(0, 0, c.width, c.height).data;
		let h = 2166136261; for (let i = 0; i < d.length; i += 7) { h ^= d[i]; h = Math.imul(h, 16777619); } return h >>> 0; })()`
	before := string(page.eval(canvasHash))
	for _, k := range []cdpKey{cdpKeyA, cdpKeyC, cdpKeyV, cdpKeyA} {
		page.press(k)
	}
	changed := false
	for deadline := time.Now().Add(30 * time.Second); time.Now().Before(deadline); time.Sleep(500 * time.Millisecond) {
		if string(page.eval(canvasHash)) != before {
			changed = true
			break
		}
	}
	page.screenshot(dump, "browser-choice-2-typed.png")
	if !changed {
		t.Fatal("the keys typed in the page did not change the screen within 30 s")
	}
	if string(page.eval(screenEndedNotice)) == "true" {
		t.Fatal("the screen ended while typing")
	}
	var shown [2]int
	_ = json.Unmarshal(page.eval(`(() => { const c = document.querySelector("canvas.screen-canvas"); return [c.width, c.height]; })()`), &shown)

	status, raw = stack.api.call(stack.operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	if status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, raw)
	}

	// The proxy's word: what was asked, what the target chose, and no graphics pipeline offered.
	asked := regexp.MustCompile(`session ` + regexp.QuoteMeta(id) + ` screen: channel "bitmap", 16 bpp asked`)
	chose := regexp.MustCompile(`the target opened the screen at (\d+) bpp \(16 asked\)`)
	var depth string
	waitUntil(t, 30*time.Second, "the proxy's word on the screen", func() bool {
		out := stack.proxyOut.String()
		m := chose.FindStringSubmatch(out)
		if m == nil || !asked.MatchString(out) {
			return false
		}
		depth = m[1]
		return true
	})
	t.Logf("the proxy: bitmap and 16 bpp asked, the target chose %s bpp", depth)
	if depth != "16" {
		t.Errorf("the target opened the screen at %s bpp, 16 asked: a policy of the target lowered or raised it", depth)
	}
	if strings.Contains(stack.proxyOut.String(), "graphics pipeline (SCREEN_RDPGFX)") {
		t.Errorf("the graphics pipeline was offered to a session opened on bitmap:\n%s", stack.proxyOut.String())
	}

	// The auditor replays the recording through the public API: complete, at the size shown.
	var replayed, keyFrames int
	var lastKey []byte
	waitUntil(t, 60*time.Second, "the sealed recording", func() bool {
		replayed, keyFrames, lastKey = 0, 0, nil
		for firstSequence := uint64(1); ; {
			status, raw := stack.api.call(stack.auditorToken, http.MethodGet, fmt.Sprintf("/sessions/%s/recording/video/segments/%d", id, firstSequence), nil)
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
			for _, f := range segment.Frames {
				replayed++
				if f.Codec == "png" {
					keyFrames++
					if data, err := base64.StdEncoding.DecodeString(f.FrameData); err == nil {
						lastKey = data
					}
				}
			}
			if segment.Complete {
				return true
			}
			firstSequence = segment.LastSequence + 1
		}
	})
	if replayed == 0 || keyFrames == 0 || lastKey == nil {
		t.Fatalf("the replay holds %d frame(s), %d key frame(s)", replayed, keyFrames)
	}
	if dump != "" {
		_ = os.WriteFile(filepath.Join(dump, "browser-choice-replay-last-key.png"), lastKey, 0o644)
	}
	img, err := png.Decode(bytes.NewReader(lastKey))
	if err != nil {
		t.Fatalf("the replay's last key frame: %v", err)
	}
	if b := img.Bounds(); b.Dx() != shown[0] || b.Dy() != shown[1] {
		t.Fatalf("the replay's last key frame is %dx%d, the page showed %dx%d", b.Dx(), b.Dy(), shown[0], shown[1])
	}
	t.Logf("replayed through the public API: %d frame(s), %d key frame(s), %dx%d as the page showed", replayed, keyFrames, shown[0], shown[1])
}

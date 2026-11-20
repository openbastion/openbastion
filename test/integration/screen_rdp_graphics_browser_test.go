package integration_test

// ADR-0101, before SCREEN_RDPGFX is turned on by default: the graphics pipeline in a real browser,
// against a real Windows. The services of the RDP flow on real processes with SCREEN_RDPGFX on, the
// Admin UI served by the Gateway, and a headless Chrome that opens the screen of an RDP session
// through the page, types into Notepad and sees the screen change. Then the proxy says the target
// opened the pipeline and how many frames it carried, and the auditor replays the recording through
// the public API: complete, at the size the page showed. Screenshots go to RDP_WINDOWS_DUMP for a
// person to judge (browser-graphics-*.png).
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
	"strconv"
	"testing"
	"time"
)

func TestScreenFlow_RDPGraphicsPipelineInAHeadlessBrowser(t *testing.T) {
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
	// A new Windows session, not the one the previous test left disconnected (freshWindowsSession).
	freshWindowsSession(t)
	stack := startRDPScreenStack(t, root, dsn, target, []string{"SCREEN_RDPGFX=true"}, []string{"ADMIN_UI_DIR=" + ui})
	status, raw := stack.api.call(stack.operatorToken, http.MethodPost, "/sessions",
		map[string]any{"targetAccountId": "acc_rdp", "protocol": "rdp", "justification": "ADR-0101", "durationMinutes": 10})
	if status != http.StatusCreated {
		t.Fatalf("RDP session: %d %s", status, raw)
	}
	id := jsonField(t, raw, "id")

	page := startHeadlessChrome(t, chrome)
	page.dump = dump
	page.viewport(1400, 1000)
	page.call("Page.navigate", map[string]any{"url": stack.gatewayURL + "/ui/"})
	page.signIn("rdp-operator", "op-password-123")
	page.showSession(id)
	page.openScreen()
	page.waitTrue("the first frame", `(() => { const c = document.querySelector("canvas.screen-canvas"); return !!c && !c.hidden && c.width > 0; })()`, 120*time.Second)
	page.eval(`document.querySelector("canvas.screen-canvas").scrollIntoView({ block: "center" }), true`)
	page.screenshot(dump, "browser-graphics-1-opened.png")

	// Notepad's text, found on the screen as the page shows it (as the clipboard test does): the
	// centre of the first all-white square of 120 pixels in the lower 70 %, in canvas pixels.
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
			page.screenshot(dump, "browser-graphics-no-notepad.png")
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

	// The keys change the screen: the canvas's pixels, hashed before and after, differ.
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
	page.screenshot(dump, "browser-graphics-2-typed.png")
	if !changed {
		t.Fatal("the keys typed in the page did not change the screen within 30 s")
	}
	if string(page.eval(screenEndedNotice)) == "true" {
		t.Fatal("the screen ended while typing")
	}
	var shown [2]int
	_ = json.Unmarshal(page.eval(`(() => { const c = document.querySelector("canvas.screen-canvas"); return [c.width, c.height]; })()`), &shown)

	// The session ends; the proxy says what the pipeline carried.
	status, raw = stack.api.call(stack.operatorToken, http.MethodDelete, "/sessions/"+id, nil)
	if status/100 != 2 {
		t.Fatalf("terminate: %d %s", status, raw)
	}
	summary := regexp.MustCompile(`graphics pipeline \(SCREEN_RDPGFX\): opened by the target (true|false), (\d+) frame\(s\) handed on`)
	var opened string
	var frames int
	waitUntil(t, 30*time.Second, "the proxy's word on the graphics pipeline", func() bool {
		m := summary.FindStringSubmatch(stack.proxyOut.String())
		if m == nil {
			return false
		}
		opened, frames = m[1], func() int { n, _ := strconv.Atoi(m[2]); return n }()
		return true
	})
	t.Logf("the proxy: graphics pipeline opened by the target %s, %d frame(s) handed on", opened, frames)
	if opened != "true" || frames == 0 {
		t.Fatalf("the screen did not come through the graphics pipeline: opened %s, %d frame(s)", opened, frames)
	}

	// The auditor replays the recording through the public API: complete, at the size shown.
	var replayed, keyFrames int
	var lastKey []byte
	waitUntil(t, 60*time.Second, "the sealed recording", func() bool {
		replayed, keyFrames, lastKey = 0, 0, nil
		for firstSequence := uint64(1); ; {
			status, raw := stack.api.call(stack.auditorToken, http.MethodGet, fmt.Sprintf("/sessions/%s/recording/video/segments/%d", id, firstSequence), nil)
			if status == http.StatusNotFound && firstSequence > 1 {
				return false
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
			// png is a key frame, the whole PNG; png-delta-v1 a partial frame (ADR-0092).
			for _, f := range segment.Frames {
				switch f.Codec {
				case "png":
					replayed++
					keyFrames++
					if data, err := base64.StdEncoding.DecodeString(f.FrameData); err == nil {
						lastKey = data
					}
				case "png-delta-v1":
					replayed++
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
	img, err := png.Decode(bytes.NewReader(lastKey))
	if err != nil {
		t.Fatalf("the replay's last key frame: %v", err)
	}
	if b := img.Bounds(); b.Dx() != shown[0] || b.Dy() != shown[1] {
		t.Fatalf("the replay's last key frame is %dx%d, the page showed %dx%d", b.Dx(), b.Dy(), shown[0], shown[1])
	}
	t.Logf("replayed through the public API: %d frame(s), %d key frame(s), %dx%d as the page showed", replayed, keyFrames, shown[0], shown[1])
}

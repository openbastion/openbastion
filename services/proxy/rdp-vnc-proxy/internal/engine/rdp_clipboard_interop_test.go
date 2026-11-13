package engine

import (
	"bytes"
	"context"
	"image"
	"image/png"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/rdp"
)

// The clipboard of ADR-0096 (increment 1) against real servers: cliprdr announced and joined, the
// exchange that opens it, then a text copied from the target and a text pasted on it.

type clipboardLog struct {
	mu     sync.Mutex
	offers int
	texts  []string
	// screen is the target's screen as the updates drew it, for a failure's capture.
	screen *rdp.RDPFramebuffer
}

// capture writes the screen as the updates drew it to RDP_WINDOWS_DUMP, when set.
func (l *clipboardLog) capture(t *testing.T, name string) {
	t.Helper()
	dir := os.Getenv("RDP_WINDOWS_DUMP")
	l.mu.Lock()
	defer l.mu.Unlock()
	if dir == "" || l.screen == nil {
		return
	}
	frame, err := l.screen.Frame(time.Now())
	if err != nil {
		t.Logf("capture: %v", err)
		return
	}
	_ = os.WriteFile(filepath.Join(dir, name), frame.PNG, 0o644)
}

// editPoint is a point in Notepad's text: the centre of the first all-white square of the screen,
// whatever size and place earlier tests left its window at. ok is false when there is none.
func (l *clipboardLog) editPoint() (x, y uint16, ok bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.screen == nil {
		return 0, 0, false
	}
	frame, err := l.screen.Frame(time.Now())
	if err != nil {
		return 0, 0, false
	}
	img, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		return 0, 0, false
	}
	return whiteSquareCentre(img, 120)
}

// whiteSquareCentre finds, scanning from the top left on an 8-pixel grid, the first side×side
// square whose every fourth pixel is white, and returns its centre. A window's text area is white;
// the desktop, the taskbar and the Start menu are not.
func whiteSquareCentre(img image.Image, side int) (uint16, uint16, bool) {
	b := img.Bounds()
	white := func(x, y int) bool {
		r, g, bl, _ := img.At(x, y).RGBA()
		return r>>8 >= 0xf8 && g>>8 >= 0xf8 && bl>>8 >= 0xf8
	}
	for y := b.Min.Y; y+side <= b.Max.Y; y += 8 {
	next:
		for x := b.Min.X; x+side <= b.Max.X; x += 8 {
			for dy := 0; dy < side; dy += 4 {
				for dx := 0; dx < side; dx += 4 {
					if !white(x+dx, y+dy) {
						continue next
					}
				}
			}
			return uint16(x + side/2), uint16(y + side/2), true
		}
	}
	return 0, 0, false
}

func (l *clipboardLog) offer() { l.mu.Lock(); l.offers++; l.mu.Unlock() }
func (l *clipboardLog) text(text string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.texts = append(l.texts, text)
	return nil
}
func (l *clipboardLog) snapshot() (int, []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.offers, append([]string(nil), l.texts...)
}

// openWithClipboard runs the connection sequence with cliprdr announced and the clipboard enabled
// both ways, and returns the session, its reader running in the background.
func openWithClipboard(t *testing.T, client *rdp.CredSSPClientSession, user, password string) (*clipboardLog, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	t.Cleanup(client.Close)
	settings := rdp.MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: rdpClientName,
		Timeout: 15 * time.Second, ClipboardChannel: true}
	log := &clipboardLog{}
	var width, height uint16
	steps := []rdpConnectionStep{
		{"MCS connect", func() error { _, e := client.ConnectMCS(ctx, settings); return e }},
		{"MCS channels", func() error {
			if e := client.EnableClipboard(true, true, log.offer, log.text); e != nil {
				return e
			}
			_, e := client.ConnectMCSChannels(ctx, 15*time.Second)
			return e
		}},
		{"client info", func() error {
			return client.SendClientInfo(ctx, rdp.RDPClientInfo{Username: user, Password: []byte(password)}, 15*time.Second)
		}},
		{"licensing", func() error { return client.CompleteLicensing(ctx, 15*time.Second) }},
		{"capabilities", func() error {
			capabilities, e := client.ExchangeCapabilities(ctx, 15*time.Second)
			width, height = capabilities.DesktopWidth, capabilities.DesktopHeight
			return e
		}},
		{"finalization", func() error { _, e := client.FinalizeConnection(ctx, 15*time.Second); return e }},
	}
	if err := runRDPConnectionSteps(ctx, steps); err != nil {
		t.Fatalf("the connection with cliprdr announced: %v", err)
	}
	if names := client.StaticChannels(); len(names) != 1 || names[0] != rdp.RDPChannelClipboard {
		t.Fatalf("channels joined: %q, want cliprdr", names)
	}
	stopped := make(chan error, 1)
	screen, err := rdp.NewRDPFramebuffer(width, height)
	if err != nil {
		t.Fatal(err)
	}
	log.screen = screen
	go func() {
		for {
			update, err := client.ReadBitmapUpdate(ctx, 2*time.Minute)
			if err != nil {
				stopped <- err
				return
			}
			if len(update.Rectangles) > 0 {
				log.mu.Lock()
				_ = log.screen.Draw(update)
				log.mu.Unlock()
			}
		}
	}()
	return log, stopped
}

func TestRDPInterop_Clipboard(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, rdpInteropPassword)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	_, stopped := openWithClipboard(t, client, rdpInteropUser, rdpInteropPassword)
	// FreeRDP's shadow server opens the clipboard, or does not: either way the session goes on, and
	// a text offered is not refused.
	time.Sleep(3 * time.Second)
	t.Logf("FreeRDP opened its clipboard: %v", client.ClipboardReady())
	if err := client.OfferClipboardText(ctx, "offered by OpenBastion"); err != nil {
		t.Fatalf("offering a text: %v", err)
	}
	select {
	case err := <-stopped:
		t.Fatalf("the session ended: %v\n%s", err, target.logs(t))
	case <-time.After(3 * time.Second):
	}
}

// sendKeys types a chord of Set-1 scancodes, pressed then released (E0-prefixed codes extended).
func sendKeys(t *testing.T, client *rdp.CredSSPClientSession, chord []uint16) {
	t.Helper()
	var events []rdp.RDPInputEvent
	key := func(code uint16, released bool) rdp.RDPInputEvent {
		return rdp.RDPInputEvent{Type: rdp.RDPInputScancode, Scancode: byte(code), Extended: code>>8 == 0xe0, Released: released}
	}
	for _, code := range chord {
		events = append(events, key(code, false))
	}
	for i := len(chord) - 1; i >= 0; i-- {
		events = append(events, key(chord[i], true))
	}
	if err := client.SendInput(context.Background(), events, 5*time.Second); err != nil {
		t.Fatalf("keys % x: %v", chord, err)
	}
	time.Sleep(300 * time.Millisecond)
}

// sameOnBothLayouts are letters at the same place in QWERTY and AZERTY, by their Set-1 scancode:
// a marker typed with them reads the same on the en-US and the fr-FR targets.
var sameOnBothLayouts = map[rune]uint16{'e': 0x12, 'r': 0x13, 't': 0x14, 'y': 0x15, 'u': 0x16, 'i': 0x17, 'o': 0x18,
	'p': 0x19, 's': 0x1f, 'd': 0x20, 'f': 0x21, 'g': 0x22, 'h': 0x23, 'j': 0x24, 'k': 0x25, 'l': 0x26,
	'x': 0x2d, 'c': 0x2e, 'v': 0x2f, 'b': 0x30, 'n': 0x31}

// The clipboard against Windows: Notepad's text copied (Ctrl+A, Ctrl+C), then a text pasted
// (Ctrl+End, Ctrl+V) and copied back. Before the logoff test, which closes the session.
func clipboardAgainstWindows(t *testing.T, client *rdp.CredSSPClientSession, user, password string) {
	t.Helper()
	log, stopped := openWithClipboard(t, client, user, password)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	waitFor := func(what string, done func() bool) {
		t.Helper()
		for deadline := time.Now().Add(30 * time.Second); !done(); {
			select {
			case err := <-stopped:
				t.Fatalf("the session ended waiting for %s: %v", what, err)
			default:
			}
			if time.Now().After(deadline) {
				offers, texts := log.snapshot()
				log.capture(t, "clipboard-failed.png")
				t.Fatalf("waited 30 s for %s: %d offer(s), %d text(s); %s (screen in clipboard-failed.png)",
					what, offers, len(texts), client.ClipboardDiagnostics())
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	time.Sleep(10 * time.Second) // the desktop, settled
	if !client.ClipboardReady() {
		t.Fatal("Windows did not open its clipboard (no Monitor Ready) in 10 s")
	}
	// Into Notepad's text, found on the screen: earlier tests leave its window at different sizes
	// and places (Windows Server 2022 at 16 bpp: 800 pixels wide at the top left, where the fixed
	// notepadPoint, three quarters of the width, fell on the desktop). Then everything selected
	// and copied.
	x, y, found := log.editPoint()
	if !found {
		x, y = notepadPoint(1280, 800)
		t.Logf("no white text area on the screen: clicking at (%d, %d)", x, y)
	}
	for _, buttons := range []rdp.RDPInputEvent{
		{Type: rdp.RDPInputMouse, PointerFlags: 0x9000, X: x, Y: y}, // PTRFLAGS_DOWN | PTRFLAGS_BUTTON1
		{Type: rdp.RDPInputMouse, PointerFlags: 0x1000, X: x, Y: y}, // PTRFLAGS_BUTTON1
	} {
		if err := client.SendInput(ctx, []rdp.RDPInputEvent{buttons}, 5*time.Second); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	letters := "ertyuiopsdfghjklxcvbn"
	marker := "obclip"
	for n := time.Now().UnixNano(); len(marker) < 14; n /= int64(len(letters)) {
		marker += string(letters[n%int64(len(letters))])
	}
	sendKeys(t, client, []uint16{0x1c}) // a line of its own
	for _, r := range marker {
		sendKeys(t, client, []uint16{sameOnBothLayouts[r]})
	}
	selectAll := []uint16{0x1d, 0x1e} // Ctrl+A
	if os.Getenv("RDP_WINDOWS_KEYBOARD") == "fr-FR" {
		selectAll = []uint16{0x1d, 0x10} // A sits where Q does in AZERTY
	}
	sendKeys(t, client, selectAll)
	sendKeys(t, client, []uint16{0x1d, 0x2e}) // Ctrl+C
	log.capture(t, "clipboard-1-copied.png")
	waitFor("Windows to offer the text it copied", func() bool { offers, _ := log.snapshot(); return offers > 0 })
	if err := client.RequestClipboardText(ctx); err != nil {
		t.Fatalf("asking for the text: %v", err)
	}
	waitFor("the text copied", func() bool { _, texts := log.snapshot(); return len(texts) > 0 })
	_, texts := log.snapshot()
	t.Logf("copied from Windows: %d characters, the marker %v", len([]rune(texts[0])), strings.Contains(texts[0], marker))
	if !strings.Contains(texts[0], marker) {
		t.Fatalf("the copied text does not hold %q", marker)
	}
	// Paste: a text offered, Notepad's text replaced by it (Ctrl+A, Ctrl+V), then copied back.
	pasted := "Pasted by OpenBastion: " + marker + " é €"
	if err := client.OfferClipboardText(ctx, pasted); err != nil {
		t.Fatalf("offering a text: %v", err)
	}
	time.Sleep(time.Second)
	sendKeys(t, client, selectAll)
	sendKeys(t, client, []uint16{0x1d, 0x2f}) // Ctrl+V
	time.Sleep(time.Second)
	sendKeys(t, client, selectAll)
	sendKeys(t, client, []uint16{0x1d, 0x2e}) // Ctrl+C
	waitFor("Windows to offer the text pasted", func() bool { offers, _ := log.snapshot(); return offers > 1 })
	if err := client.RequestClipboardText(ctx); err != nil {
		t.Fatalf("asking for the text again: %v", err)
	}
	waitFor("the pasted text, copied back", func() bool { _, texts := log.snapshot(); return len(texts) > 1 })
	_, texts = log.snapshot()
	if !strings.Contains(texts[len(texts)-1], pasted) {
		t.Fatalf("Notepad holds %q after the paste, want %q", texts[len(texts)-1], pasted)
	}
	t.Logf("pasted on Windows and copied back: %q", pasted)
}

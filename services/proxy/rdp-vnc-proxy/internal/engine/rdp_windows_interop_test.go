package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"image/png"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// A real Windows (ADR-0071, "reste à valider"): Windows Server 2022 run by dockur/windows in CI
// (test/integration/testdata/rdp/windows, .github/workflows/windows-rdp.yml), or any Windows the
// variables name. The certificate the target presents is the one the test issued: the pin and the
// roots are known before the target starts, nothing is learnt from it.
//
//	set -a; . "$DIR/test.env"; set +a; make test-rdp-windows
//
// What this cannot see on its own — pixel fidelity — it leaves in RDP_WINDOWS_DUMP for a person.
type rdpWindowsTarget struct {
	address, user, password, pin, name string
	roots                              *x509.CertPool
}

var (
	rdpWindowsOnce  sync.Once
	rdpWindowsReady error
)

// notepadPoint is where a click gives Notepad the keyboard: in its window, right of the Start
// menu. At the screen's centre, a Start menu left open (Ctrl+Esc opens it, Esc did not always close
// it) took the click, and the keys after it went to its search (CI of PR #157, 32 bpp, captures
// extended-1b and extended-3). A click outside the menu closes it.
func notepadPoint(width, height uint32) (uint16, uint16) {
	return notepadX(int(width)), uint16(height / 2)
}

func notepadX(width int) uint16 { return uint16(width * 3 / 4) }

func windowsTarget(t *testing.T) rdpWindowsTarget {
	t.Helper()
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	target := rdpWindowsTarget{address: os.Getenv("RDP_WINDOWS_ADDRESS"), user: os.Getenv("RDP_WINDOWS_USER"),
		password: os.Getenv("RDP_WINDOWS_PASSWORD"), pin: os.Getenv("RDP_WINDOWS_PIN"), name: os.Getenv("RDP_WINDOWS_SERVER_NAME")}
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatalf("RDP_WINDOWS_CA_FILE: %v", err)
	}
	target.roots = x509.NewCertPool()
	if !target.roots.AppendCertsFromPEM(raw) || target.address == "" || target.user == "" || target.password == "" || target.pin == "" || target.name == "" {
		t.Fatal("RDP_WINDOWS_ADDRESS, _USER, _PASSWORD, _PIN, _SERVER_NAME and _CA_FILE are all needed")
	}
	// The installation is over when the target presents the pinned certificate: install.bat puts it
	// there at its very end. Waited for once, for every test of the run.
	rdpWindowsOnce.Do(func() {
		wait := 90 * time.Minute
		if v, err := time.ParseDuration(os.Getenv("RDP_WINDOWS_WAIT")); err == nil {
			wait = v
		}
		deadline, last := time.Now().Add(wait), time.Time{}
		for {
			transport, err := rdp.DialHybrid(context.Background(), rdp.TransportConfig{Address: target.address, TLSFingerprint: target.pin,
				TLSRoots: target.roots, TLSServerName: target.name, DialTimeout: 10 * time.Second})
			// Ready once it presents the pinned certificate and, where the share is known, once
			// rdp-setup.ps1 has said its restart of Remote Desktop Services is over: the certificate
			// takes effect before that restart, which then cut the first tests (CI of #144, #155, #157).
			readyFile := ""
			if shared := os.Getenv("RDP_WINDOWS_SHARED"); shared != "" {
				readyFile = filepath.Join(shared, "rdp-ready.txt")
			}
			_, readyErr := os.Stat(readyFile)
			if err == nil {
				_ = transport.Close()
			}
			if err == nil && (readyFile == "" || readyErr == nil) {
				t.Logf("the target presents the pinned certificate, its restart over")
				return
			}
			if err == nil {
				err = fmt.Errorf("the pinned certificate is presented, but %s is not there yet", readyFile)
			}
			if time.Now().After(deadline) {
				rdpWindowsReady = err
				return
			}
			if time.Since(last) > time.Minute {
				t.Logf("waiting for the target (%v): %v", time.Until(deadline).Round(time.Minute), err)
				last = time.Now()
			}
			time.Sleep(10 * time.Second)
		}
	})
	if rdpWindowsReady != nil {
		t.Fatalf("the target never presented the pinned certificate: %v", rdpWindowsReady)
	}
	return target
}

func (w rdpWindowsTarget) authenticate(ctx context.Context, pin, password string) (*rdp.CredSSPClientSession, error) {
	transport, err := rdp.DialHybrid(ctx, rdp.TransportConfig{
		Address: w.address, TLSFingerprint: pin, TLSRoots: w.roots, TLSServerName: w.name, DialTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	session, err := transport.EstablishCredSSP(ctx, rdp.CredSSPClientConfig{
		Version: 6, Username: w.user, Password: []byte(password), Timeout: 15 * time.Second,
	})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return session, nil
}

func TestRDPWindows_CredSSP(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	t.Run("Windows accepts the proof, NLA on, and this client the server's", func(t *testing.T) {
		session, err := target.authenticate(ctx, target.pin, target.password)
		if err != nil {
			// What ADR-0071 asks: does Windows want request-mic, or count the sequences otherwise?
			t.Fatalf("CredSSP with Windows: %v", err)
		}
		session.Close()
	})
	t.Run("a wrong password is refused by Windows authentication", func(t *testing.T) {
		session, err := target.authenticate(ctx, target.pin, target.password+"-not")
		if err == nil {
			session.Close()
			t.Fatal("Windows accepted a wrong password")
		}
		// A protocol/binding failure is not evidence that Windows rejected the credentials.
		// Windows reports STATUS_LOGON_FAILURE or STATUS_WRONG_PASSWORD in TSRequest.errorCode.
		if !strings.Contains(err.Error(), "NTSTATUS 0xC000006D") &&
			!strings.Contains(err.Error(), "NTSTATUS 0xC000006A") {
			t.Fatalf("Windows did not return an authentication refusal status: %v", err)
		}
		t.Logf("Windows refused the credentials: %v", err)
	})
	t.Run("an impostor's pin stops before any CredSSP byte", func(t *testing.T) {
		if _, err := target.authenticate(ctx, strings.Repeat("0", 64), target.password); !errors.Is(err, rdp.ErrTLSVerification) {
			t.Fatalf("%v, want ErrTLSVerification", err)
		}
	})
}

func TestRDPWindows_Screen(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	codec := &RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}
	session, err := codec.Open(ctx, cred)
	if err != nil {
		var failure *proxycore.ScreenFailure
		if errors.As(err, &failure) {
			t.Fatalf("opening the screen of Windows: %v: %v", err, failure.Err)
		}
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	frames := 0
	next := func(limit time.Duration) (screenstream.Message, bool) {
		select {
		case message, ok := <-session.Frames():
			if !ok {
				// A Fast-Path fragment, a reactivation or an update outside the closed list of
				// increment 71 ends the stream: what ADR-0071 asks to find out.
				t.Fatalf("the stream ended after %d frame(s): %v", frames, session.Err())
			}
			frames++
			return message, true
		case <-time.After(limit):
			return screenstream.Message{}, false
		}
	}
	settle := func(frame screenstream.Message, quiet time.Duration) screenstream.Message {
		for {
			following, ok := next(quiet)
			if !ok {
				return frame
			}
			frame = following
		}
	}
	dump := func(name string, frame screenstream.Message) {
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, name), frame.PNG, 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
	// The logon runs Notepad (rdp-setup.ps1): the desktop takes its time to settle.
	first, ok := next(90 * time.Second)
	if !ok {
		t.Fatalf("no frame from Windows in 90 s: %v", session.Err())
	}
	// The session opens, then Notepad starts, sometimes more than 10 s later (CI runs #43 and #44:
	// the click came before Notepad, and the change the test saw was Notepad appearing, not the
	// keys). So: quiet, then one more change within 60 s (Notepad), then quiet again. When Notepad
	// is already there, the minute is all that is lost.
	before := settle(first, 10*time.Second)
	if appeared, ok := next(60 * time.Second); ok {
		before = settle(appeared, 10*time.Second)
	}
	dump("windows-before.png", before)
	t.Logf("Windows' desktop: %dx%d, %d frame(s) to settle", before.Width, before.Height, frames)
	// A screen is not a session: Windows' logon screen streams as well as a desktop, and keys reach
	// it (CI runs #39 and #42). Windows says when the user's session opened; without that, the
	// target did not open it with the delegated credentials.
	logonNotified, depth := false, uint16(0)
	if adapter, ok := session.(*rdpScreenSessionAdapter); ok {
		if target, ok := adapter.target.(*rdpTargetSession); ok {
			logonNotified, depth = target.session.LogonNotified(), target.session.BitsPerPixel()
		}
	}
	// The depth the target allows (prepare.sh DIR DEPTH): 16 as installed, 32 by policy.
	if want := os.Getenv("RDP_WINDOWS_BPP"); want != "" && want != strconv.Itoa(int(depth)) {
		t.Fatalf("the session is at %d bpp, the target allows %s", depth, want)
	}
	t.Logf("session at %d bpp", depth)
	if !logonNotified {
		t.Fatal("Windows did not say the session opened: this is its logon screen, not the session the delegated credentials should open (windows-before.png)")
	}
	if len(before.PNG) == 0 || before.Width == 0 || before.Height == 0 {
		t.Fatalf("frame: %d bytes, %dx%d", len(before.PNG), before.Width, before.Height)
	}
	// Into Notepad, in the middle of the desktop, then a word and Enter.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: uint16(before.Width / 2), Y: uint16(before.Height / 2), Buttons: 1}); err != nil {
		t.Fatalf("pointer: %v", err)
	}
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: uint16(before.Width / 2), Y: uint16(before.Height / 2)}); err != nil {
		t.Fatalf("pointer: %v", err)
	}
	// At a person's pace: a second after the click, 50 ms between events. Sent microseconds after
	// the click, Windows routed keys before Notepad had the focus, and lost some (CI runs #48 and
	// #49, with and without KBDFLAGS_DOWN); the keyboard isolation, a second after its click, lost
	// none at 16 and 32 bpp.
	time.Sleep(time.Second)
	for _, scancode := range []uint16{0x18, 0x30, 0x1c} { // o, b, Enter
		for _, flags := range []uint8{screenstream.KeyPressed, screenstream.KeyReleased} {
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: scancode, Flags: flags}); err != nil {
				t.Fatalf("input: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	changed, ok := next(20 * time.Second)
	if !ok {
		t.Fatalf("the screen of Windows did not change after the keys: %v", session.Err())
	}
	after := settle(changed, 5*time.Second)
	dump("windows-after.png", after)
	if bytes.Equal(after.PNG, before.PNG) {
		t.Fatal("the screen came back identical: the input changed nothing")
	}
	t.Logf("%d frame(s) in all; the dumps show what a person must judge (pixel fidelity, text)", frames)
}

// The pointer drawn into the frames (ADR-0091), against Windows: its shapes stay within the profile,
// and the operator's pointer is in the frame. Before the logoff test, which closes the session.
func TestRDPWindows_Pointer(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second, DrawPointer: true}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows, the pointer drawn: %v", err)
	}
	defer session.Close()
	provePointerIsDrawn(t, session, true, func(name string, frame screenstream.Message) {
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, name), frame.PNG, 0o644)
		}
	})
}

// The keyboard layouts (ADR-0071's exit criterion, ADR-0088): the operator sends physical keys
// (scancodes) and the target reads them with its own layout. Keys whose character differs between
// QWERTY and AZERTY are typed into Notepad, which saves them (Ctrl+S, "kbd"); rdp-setup.ps1 copies
// the file to the share the runner reads, and the text is compared to what the target's layout
// gives — the text, not a picture of it.
func TestRDPWindows_KeyboardLayout(t *testing.T) {
	target := windowsTarget(t)
	shared := os.Getenv("RDP_WINDOWS_SHARED")
	if shared == "" {
		t.Skip("RDP_WINDOWS_SHARED not set: the share rdp-setup.ps1 copies Notepad's file to (prepare.sh)")
	}
	// Q, W, A, Z, the key right of L, M, the key right of M, 1, then Shift+1.
	keys := []uint16{0x10, 0x11, 0x1e, 0x2c, 0x27, 0x32, 0x33, 0x02}
	want := map[string]string{"en-US": "qwaz;m,1!", "fr-FR": "azqwm,;&1"}[os.Getenv("RDP_WINDOWS_KEYBOARD")]
	if want == "" {
		want = "qwaz;m,1!" // prepare.sh's default, en-US
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	var last screenstream.Message
	settle := func(quiet, limit time.Duration) {
		end := time.After(limit)
		for {
			select {
			case m, ok := <-session.Frames():
				if !ok {
					t.Fatalf("the stream ended: %v", session.Err())
				}
				last = m
			case <-time.After(quiet):
				return
			case <-end:
				return
			}
		}
	}
	settle(10*time.Second, 90*time.Second)
	if last.Width == 0 {
		t.Fatal("no frame from Windows")
	}
	press := func(code uint16, pressed bool) {
		flags := screenstream.KeyReleased
		if pressed {
			flags = screenstream.KeyPressed
		}
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: code, Flags: flags}); err != nil {
			t.Fatalf("key 0x%x: %v", code, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	key := func(code uint16) { press(code, true); press(code, false) }
	chord := func(modifier, code uint16) { press(modifier, true); key(code); press(modifier, false) }
	// Into Notepad, at the end of what the other tests typed, on a line of its own.
	x, y := notepadPoint(last.Width, last.Height)
	for _, buttons := range []byte{1, 0} {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: x, Y: y, Buttons: buttons}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	chord(0x1d, 0xe04f) // Ctrl+End
	key(0x1c)
	for _, code := range keys {
		key(code)
	}
	chord(0x2a, 0x02) // Shift+1
	settle(2*time.Second, 10*time.Second)
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "keyboard-typed.png"), last.PNG, 0o644)
	}
	// Ctrl+S, then the name "kbd" in Save As: S, K, B and D are where QWERTY and AZERTY agree.
	chord(0x1d, 0x1f)
	settle(2*time.Second, 10*time.Second)
	for _, code := range []uint16{0x25, 0x30, 0x20} {
		key(code)
	}
	key(0x1c)
	settle(2*time.Second, 10*time.Second)
	path := filepath.Join(shared, "kbd.txt")
	var raw []byte
	for deadline := time.Now().Add(2 * time.Minute); ; {
		if raw, err = os.ReadFile(path); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("Notepad's file never reached the share (%s): %v", path, err)
		}
		time.Sleep(5 * time.Second)
	}
	text := strings.TrimPrefix(string(raw), "\xef\xbb\xbf") // a UTF-8 BOM, if Notepad wrote one
	lines := strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n")
	got := ""
	for i := len(lines) - 1; i >= 0; i-- {
		if strings.TrimSpace(lines[i]) != "" {
			got = lines[i]
			break
		}
	}
	t.Logf("layout %s: typed %q", os.Getenv("RDP_WINDOWS_KEYBOARD"), got)
	if got != want {
		t.Fatalf("the target read %q, want %q for layout %q", got, want, os.Getenv("RDP_WINDOWS_KEYBOARD"))
	}
}

// The extended keys (E0-prefixed scancodes, KBDFLAGS_EXTENDED), against Windows (ADR-0071, ADR-0088).
// PR #101 saw the Windows key not reach Windows' shell: Win+R typed "r" into Notepad. Measured here,
// key by key, by what the operator's path sends (the codec's Input):
//   - the Windows key alone opens the Start menu, as Ctrl+Esc does: measured by the share of the
//     screen it changes;
//   - Ctrl+Alt+Del, as the Admin UI's button sends it, which should show the security screen: a PNG;
//   - keys whose character proves the flag, read back from Notepad's file: the keypad's "/" (E0 35;
//     without the flag, the key right of the full stop, "!" in AZERTY), and in AZERTY AltGr (E0 38)
//     with 0 and E, "@" and "€" (without the flag, AltGr is Alt).
//
// Before the logoff test, which closes the session.
func TestRDPWindows_ExtendedKeys(t *testing.T) {
	target := windowsTarget(t)
	shared := os.Getenv("RDP_WINDOWS_SHARED")
	if shared == "" {
		t.Skip("RDP_WINDOWS_SHARED not set: the share Notepad's file comes back through (prepare.sh)")
	}
	azerty := os.Getenv("RDP_WINDOWS_KEYBOARD") == "fr-FR"
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	var last screenstream.Message
	settle := func(quiet, limit time.Duration) {
		end := time.After(limit)
		for {
			select {
			case m, ok := <-session.Frames():
				if !ok {
					t.Fatalf("the stream ended: %v", session.Err())
				}
				last = m
				continue
			case <-time.After(quiet):
			case <-end:
			}
			return
		}
	}
	dump := func(name string) {
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && last.PNG != nil {
			_ = os.WriteFile(filepath.Join(dir, name), last.PNG, 0o644)
		}
	}
	press := func(code uint16, pressed bool) {
		flags := screenstream.KeyReleased
		if pressed {
			flags = screenstream.KeyPressed
		}
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: code, Flags: flags}); err != nil {
			t.Fatalf("key 0x%x: %v", code, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	key := func(code uint16) { press(code, true); press(code, false) }
	chord := func(modifier, code uint16) { press(modifier, true); key(code); press(modifier, false) }
	settle(10*time.Second, 90*time.Second)
	dump("extended-0-desktop.png")

	// The Start menu covers a good part of the screen: a key that opens it changes at least 2 % of
	// the pixels, which the cursor's blink never does.
	opens := func(what string, keys func(), name string) float64 {
		t.Helper()
		before := last
		keys()
		settle(2*time.Second, 6*time.Second)
		dump(name)
		changed := changedFraction(t, before, last)
		key(0x01) // Esc
		settle(2*time.Second, 6*time.Second)
		t.Logf("%s: %.1f %% of the screen changed (%s)", what, 100*changed, name)
		return changed
	}
	// Ctrl+Esc opens the Start menu with no extended key: the check that the menu opens on this
	// machine, and that the measure sees it.
	if changed := opens("Ctrl+Esc", func() { chord(0x1d, 0x01) }, "extended-1b-ctrl-esc.png"); changed < 0.02 {
		t.Fatalf("Ctrl+Esc changed %.1f %% of the screen: the Start menu does not open here, the Windows key cannot be judged", 100*changed)
	}
	// The Windows key alone opens it too (PR #101, #119: it did not; INFO_ENABLEWINDOWSKEY).
	if changed := opens("the Windows key", func() { key(0xe05b) }, "extended-1-windows-key.png"); changed < 0.02 {
		t.Fatalf("the Windows key changed %.1f %% of the screen: it did not open the Start menu (extended-1-windows-key.png)", 100*changed)
	}

	for _, code := range []uint16{0x1d, 0x38, 0xe053} { // Ctrl+Alt+Del, as the Admin UI's button
		press(code, true)
	}
	for _, code := range []uint16{0xe053, 0x38, 0x1d} {
		press(code, false)
	}
	settle(2*time.Second, 8*time.Second)
	dump("extended-2-ctrl-alt-del.png")
	key(0x01) // Esc: back to the desktop
	settle(2*time.Second, 8*time.Second)

	// Into Notepad, a line of its own, then the keys the flag decides; Ctrl+S saves kbd.txt again.
	x, y := notepadPoint(last.Width, last.Height)
	for _, buttons := range []byte{1, 0} {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: x, Y: y, Buttons: buttons}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	chord(0x1d, 0xe04f) // Ctrl+End
	key(0x1c)
	key(0xe035) // keypad "/"
	want := "/"
	if azerty {
		chord(0xe038, 0x0b) // AltGr+0: "@"
		chord(0xe038, 0x12) // AltGr+E: "€"
		want = "/@€"
	}
	settle(2*time.Second, 6*time.Second)
	dump("extended-3-typed.png")
	chord(0x1d, 0x1f) // Ctrl+S: kbd.txt, saved before by the keyboard test
	settle(2*time.Second, 6*time.Second)

	path := filepath.Join(shared, "kbd.txt")
	got := ""
	for deadline := time.Now().Add(2 * time.Minute); ; {
		if raw, err := os.ReadFile(path); err == nil {
			lines := strings.Split(strings.ReplaceAll(strings.TrimPrefix(string(raw), "\xef\xbb\xbf"), "\r\n", "\n"), "\n")
			for i := len(lines) - 1; i >= 0; i-- {
				if strings.TrimSpace(lines[i]) != "" {
					got = lines[i]
					break
				}
			}
			if got == want {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("Notepad's last line is %q, want %q: an extended key did not reach Windows as one (extended-3-typed.png)", got, want)
		}
		time.Sleep(5 * time.Second)
	}
	t.Logf("extended keys read back as %q; the Windows key and Ctrl+Alt+Del are in extended-1 and extended-2 PNGs", got)
}

// The measurements of ADR-0090 (lot A) against Windows: in Notepad, an idle desktop, a key's way
// to the screen, typing, a window of dense text, scrolling, and the drawn pointer. The figures go to
// the log (MEASURE) and to measure.json beside the screens. Before the logoff test, which closes the
// session; Notepad is emptied and saved at the end, so that nothing asks to be saved at logoff.
// The scenes run twice: whole frames, then partial frames (ADR-0092), for the figures of both.
func TestRDPWindows_Measure(t *testing.T) {
	for _, partial := range []bool{false, true} {
		name := "whole-frames"
		if partial {
			name = "partial-frames"
		}
		t.Run(name, func(t *testing.T) { measureWindows(t, partial) })
	}
}

func measureWindows(t *testing.T, partial bool) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	// As the proxy runs by default: the pointer drawn, at most one frame each 50 ms.
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second, DrawPointer: true,
		FrameInterval: 50 * time.Millisecond, PartialFrames: partial}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	label := fmt.Sprintf("windows-%s-%sbpp-%s-%s", os.Getenv("RDP_WINDOWS_VERSION"), os.Getenv("RDP_WINDOWS_BPP"),
		os.Getenv("RDP_WINDOWS_SESSION"), os.Getenv("RDP_WINDOWS_KEYBOARD"))
	dump := os.Getenv("RDP_WINDOWS_DUMP")
	if partial {
		label += "-partial"
		if dump != "" {
			dump = filepath.Join(dump, "partial")
			_ = os.MkdirAll(dump, 0o755)
		}
	}
	m := newSessionMeter(t, label, session, rdpServerBytes(t, session))
	m.settle(10*time.Second, 90*time.Second)
	m.mu.Lock()
	width, height := int(m.last.Width), int(m.last.Height)
	m.mu.Unlock()
	if width == 0 {
		t.Fatal("no frame from Windows")
	}
	ctrl, ctrlA := uint16(0x1d), uint16(0x1e)
	if os.Getenv("RDP_WINDOWS_KEYBOARD") == "fr-FR" {
		ctrlA = 0x10 // A sits where Q does in AZERTY
	}
	// Into Notepad, at the end of its text, on a line of its own.
	for _, buttons := range []byte{1, 0} {
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: notepadX(width), Y: uint16(height / 2), Buttons: buttons}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(time.Second)
	rdpChord(t, session, ctrl, 0xe04f) // Ctrl+End
	rdpKeys(t, session, 50*time.Millisecond, 0x1c)
	m.settle(2*time.Second, 20*time.Second)

	m.scene("idle", func() { time.Sleep(10 * time.Second) })
	m.latency("key-to-frame", 10, func() { rdpKeys(t, session, 0, 0x2d) }, func() { rdpKeys(t, session, 0, 0x0e) })
	m.scene("typing", func() { rdpKeys(t, session, 30*time.Millisecond, append(rdpSentence, 0x1c)...) })
	// Seven doublings of Notepad's text: a window full of lines, out of any scene.
	for i := 0; i < 7; i++ {
		rdpChord(t, session, ctrl, ctrlA)
		rdpChord(t, session, ctrl, 0x2e) // Ctrl+C
		rdpChord(t, session, ctrl, 0xe04f)
		rdpChord(t, session, ctrl, 0x2f) // Ctrl+V
		m.settle(time.Second, 20*time.Second)
	}
	m.scene("dense-text", func() { rdpChord(t, session, ctrl, 0xe047) }) // Ctrl+Home: the window repainted, full of text
	m.mu.Lock()
	dense := m.last
	m.mu.Unlock()
	m.scene("scrolling", func() {
		for i := 0; i < 20; i++ {
			rdpKeys(t, session, 150*time.Millisecond, 0xe051) // Page Down
		}
	})
	m.scene("pointer", func() { m.pointerCircle(width/2, height/2, 200, 50, 20*time.Millisecond) })
	// A video (ADR-0090, lot A): the whole screen changing 25 times a second, for 10 s, played by
	// rdp-video.ps1 when asked through the share (the Windows key does not reach the shell, so no
	// program can be started from the keyboard). Random 8-pixel blocks: the worst case for PNG.
	if shared := os.Getenv("RDP_WINDOWS_SHARED"); shared != "" {
		video := m.scene("video", func() {
			if err := os.WriteFile(filepath.Join(shared, "video-request"), []byte("10\n"), 0o644); err != nil {
				t.Fatalf("asking for the video: %v", err)
			}
			time.Sleep(12 * time.Second) // the request seen within 250 ms, the window up within a second or two
		})
		if video.Frames < 50 {
			t.Errorf("the video scene made %d frame(s): rdp-video.ps1 did not play (video-status-*.txt on the share)", video.Frames)
		}
		// Notepad again, the window closed: the clean-up below types into it.
		for _, buttons := range []byte{1, 0} {
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: notepadX(width), Y: uint16(height / 2), Buttons: buttons}); err != nil {
				t.Fatal(err)
			}
		}
		m.settle(2*time.Second, 20*time.Second)
	}
	if dump != "" && dense.Type == screenstream.TypeFrame {
		_ = os.WriteFile(filepath.Join(dump, "measure-dense-text.png"), dense.PNG, 0o644)
	}
	// Nothing left to save at logoff: the text emptied, the file saved.
	rdpChord(t, session, ctrl, ctrlA)
	rdpKeys(t, session, 50*time.Millisecond, 0xe053) // Delete
	rdpChord(t, session, ctrl, 0x1f)                 // Ctrl+S
	m.settle(2*time.Second, 20*time.Second)
	m.publish(dump)
}

// The static channel of ADR-0095 (increment 1) against Windows: drdynvc announced, given an ID,
// joined, and what Windows sends on it read off the screen's stream (rdp_channel_interop_test.go).
// The first message should be the capabilities request (Cmd 5); what follows says which dynamic
// channels Windows proposes, for increment 2. Before the logoff test, which closes the session.
func TestRDPWindows_StaticChannel(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, target.pin, target.password)
	if err != nil {
		t.Fatal(err)
	}
	messages := openWithStaticChannel(t, client, target.user, target.password, 20*time.Second)
	if len(messages) == 0 {
		t.Fatal("nothing from Windows on drdynvc in 20 s")
	}
	if messages[0][0]>>4 != 0x05 {
		t.Fatalf("Windows' first drdynvc message has Cmd %d, not the capabilities request (5)", messages[0][0]>>4)
	}
}

// The dynamic channels of ADR-0095 (increment 2) against Windows: the display control opened, the
// other names Windows proposes refused (logged), and the display control's capabilities received.
func TestRDPWindows_DynamicChannels(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, target.pin, target.password)
	if err != nil {
		t.Fatal(err)
	}
	dynamic := readDynamicChannels(t, client, target.user, target.password, 20*time.Second)
	dynamic.mu.Lock()
	defer dynamic.mu.Unlock()
	if len(dynamic.opened) != 1 || dynamic.opened[0] != rdp.RDPDisplayControlChannel {
		t.Fatalf("opened %q, want the display control alone", dynamic.opened)
	}
	caps := dynamic.messages[rdp.RDPDisplayControlChannel]
	if len(caps) == 0 || len(caps[0]) < 8 || binary.LittleEndian.Uint32(caps[0][:4]) != 5 {
		t.Fatalf("no DISPLAYCONTROL_CAPS_PDU from Windows: %d message(s)", len(caps))
	}
}

// The resize of ADR-0095 (increment 3) against Windows, through the codec as the proxy runs it with
// SCREEN_RESIZE on: the display control opened, its capabilities read, then InputResize asks for
// 1024 x 768 and Windows reactivates at that size; the frames follow. The size asked is odd on
// purpose: it is brought to the bounds first (1023 -> 1022).
func TestRDPWindows_Resize(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second, DrawPointer: true,
		FrameInterval: 50 * time.Millisecond, Resize: true}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	if resizer, ok := session.(proxycore.Resizer); !ok || !resizer.Resizable() {
		t.Fatal("the session does not say it resizes: the HELLO would not tell the browser")
	}
	sizeOf := func(m screenstream.Message) [2]uint32 { return [2]uint32{m.Width, m.Height} }
	var first screenstream.Message
	select {
	case first = <-session.Frames():
	case <-time.After(90 * time.Second):
		t.Fatalf("no frame from Windows: %v", session.Err())
	}
	t.Logf("first frame %dx%d", first.Width, first.Height)
	want := [2]uint32{1022, 768}
	for deadline := time.After(60 * time.Second); ; {
		// The capabilities come over the display control once it opens: asked every 2 s until a frame
		// of the size comes, the codec ignoring what comes before them.
		if err := session.Input(screenstream.InputEvent{Type: screenstream.InputResize, X: 1023, Y: 768}); err != nil {
			t.Fatalf("resize refused: %v", err)
		}
		select {
		case m, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended: %v", session.Err())
			}
			if sizeOf(m) == want {
				t.Logf("a %dx%d frame (sequence %d, type %d): Windows followed the resize", m.Width, m.Height, m.Sequence, m.Type)
				if m.Type != screenstream.TypeFrame {
					t.Fatalf("the first frame at the new size is not a key frame (type %d)", m.Type)
				}
				return
			}
		case <-time.After(2 * time.Second):
		case <-deadline:
			diagnosis := "not an RDP target session"
			if adapter, ok := session.(*rdpScreenSessionAdapter); ok {
				if target, ok := adapter.target.(*rdpTargetSession); ok {
					target.displayMu.Lock()
					diagnosis = fmt.Sprintf("display control caps %+v (received %v), %d layout(s) sent, %d kept back by a closed channel",
						target.displayCaps, target.displayReady, target.resizesSent, target.resizesDeferred)
					target.displayMu.Unlock()
				}
			}
			t.Fatalf("no %dx%d frame within 60 s of the resize: %v; %s", want[0], want[1], session.Err(), diagnosis)
		}
	}
}

// The clipboard of ADR-0096 (increment 1) against Windows: Notepad's text copied, then a text
// pasted in it and copied back (rdp_clipboard_interop_test.go).
func TestRDPWindows_Clipboard(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	client, err := target.authenticate(ctx, target.pin, target.password)
	if err != nil {
		t.Fatal(err)
	}
	clipboardAgainstWindows(t, client, target.user, target.password)
}

// The target ending the session (ADR-0071 §3, "Fin"): Windows logs the user's session off, asked by
// a file the runner puts on the share (rdp-setup.ps1's SYSTEM loop, every 30 s). The keys did not
// do it: the Windows key never reached the shell (PR #101, captures). The stream ends with no
// error, which the relay says as session_ended. Last in this file: it closes the user's session,
// and the next connection opens a new one.
func TestRDPWindows_LogoffEndsTheSession(t *testing.T) {
	target := windowsTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("opening the screen of Windows: %v", err)
	}
	defer session.Close()
	// What was on the screen at each step, to judge by eye when the logoff does not end the stream.
	var last screenstream.Message
	dump := func(name string) {
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && last.PNG != nil {
			_ = os.WriteFile(filepath.Join(dir, name), last.PNG, 0o644)
		}
	}
	settle := func(quiet, limit time.Duration) int {
		frames := 0
		end := time.After(limit)
		for {
			select {
			case m, ok := <-session.Frames():
				if !ok {
					t.Fatalf("the stream ended before the logoff: %v", session.Err())
				}
				last, frames = m, frames+1
				continue
			case <-time.After(quiet):
			case <-end:
			}
			return frames
		}
	}
	// The desktop, settled.
	settle(10*time.Second, 90*time.Second)
	dump("logoff-0-desktop.png")
	shared := os.Getenv("RDP_WINDOWS_SHARED")
	if shared == "" {
		t.Skip("RDP_WINDOWS_SHARED not set: the share the logoff is asked through (prepare.sh)")
	}
	if err := os.WriteFile(filepath.Join(shared, "logoff-request"), []byte("logoff\n"), 0o644); err != nil {
		t.Fatalf("asking for the logoff: %v", err)
	}
	frames := 0
	defer func() {
		t.Logf("%d frame(s) after the logoff was asked", frames)
		dump("logoff-3-last.png")
	}()
	for deadline := time.After(3 * time.Minute); ; {
		select {
		case m, ok := <-session.Frames():
			if ok {
				last, frames = m, frames+1
				continue
			}
			if err := session.Err(); err != nil {
				t.Fatalf("Windows' logoff was taken for a failure: %v", err)
			}
			t.Log("the logoff ended the stream with no error: session_ended")
			return
		case <-deadline:
			t.Fatal("the stream did not end within 3 minutes of the logoff request")
		}
	}
}

// changedFraction is the share of the pixels that differ between two whole frames of one size.
func changedFraction(t *testing.T, a, b screenstream.Message) float64 {
	t.Helper()
	if a.Type != screenstream.TypeFrame || b.Type != screenstream.TypeFrame {
		t.Fatalf("frames of type %d and %d: whole frames needed", a.Type, b.Type)
	}
	ia, err := png.Decode(bytes.NewReader(a.PNG))
	if err != nil {
		t.Fatal(err)
	}
	ib, err := png.Decode(bytes.NewReader(b.PNG))
	if err != nil {
		t.Fatal(err)
	}
	r := ia.Bounds()
	if r != ib.Bounds() || r.Empty() {
		return 1 // another size: the screen changed whole
	}
	changed := 0
	for y := r.Min.Y; y < r.Max.Y; y++ {
		for x := r.Min.X; x < r.Max.X; x++ {
			if ia.At(x, y) != ib.At(x, y) {
				changed++
			}
		}
	}
	return float64(changed) / float64(r.Dx()*r.Dy())
}

package engine

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
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
			if err == nil {
				_ = transport.Close()
				t.Logf("the target presents the pinned certificate")
				return
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
	x, y := uint16(last.Width/2), uint16(last.Height/2)
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

// The target ending the session (ADR-0071 §3, "Fin"): the user logs off (Win+R, "logoff", Enter;
// keys that QWERTY and AZERTY share). Windows ends the connection the way the protocol does, and
// the stream ends with no error, which the relay says as session_ended. Last in this file: it
// closes the user's session, and the next connection opens a new one.
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
	press(0xe05b, true) // Win+R
	key(0x13)
	press(0xe05b, false)
	settle(2*time.Second, 5*time.Second)
	dump("logoff-1-run.png")
	for _, code := range []uint16{0x26, 0x18, 0x22, 0x18, 0x21, 0x21} { // l o g o f f
		key(code)
	}
	settle(time.Second, 3*time.Second)
	dump("logoff-2-typed.png")
	key(0x1c) // Enter
	frames := 0
	defer func() {
		t.Logf("%d frame(s) after Enter", frames)
		dump("logoff-3-last.png")
	}()
	for deadline := time.After(90 * time.Second); ; {
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
			t.Fatal("the stream did not end after the logoff")
		}
	}
}

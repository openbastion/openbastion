package rdp

// ADR-0071, the Windows validation, the reactivation (MS-RDPBCGR 1.3.1.3). Windows never sent this
// client a Deactivate All: it opens the session with the credentials CredSSP delegated, at the
// size the client asked for. The case where it must: a target that always prompts for the password
// (the policy fPromptForPassword, prepare.sh DIR 16 prompt). The connection then starts on
// Windows' logon screen, in a session of its own; once the password is typed, Windows hands over
// the user's session. When that session already exists, disconnected, the connection moves to it:
// a Deactivate All, a new Demand Active, the finalization again.
//
// Two connections, each through the codec's own ReadBitmapUpdate, which follows reactivations:
// the first types the password on the logon screen (a session opens), then leaves it
// disconnected; the second types it again, and Windows should move it to that session. Each
// writes what it saw (reactivations, logon notification, size) and the screens before and after
// the password, as PNGs to judge by eye.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_Reactivation -v

import (
	"context"
	"crypto/x509"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// usScancode is the US layout of the characters a test password holds (prepare.sh: "Ob-", hex,
// "-W1"), as Set-1 make codes; true when Shift is needed.
func usScancode(r rune) (byte, bool, bool) {
	const letters = "\x1e\x30\x2e\x20\x12\x21\x22\x23\x17\x24\x25\x26\x32\x31\x18\x19\x10\x13\x1f\x14\x16\x2f\x11\x2d\x15\x2c"
	switch {
	case r >= 'a' && r <= 'z':
		return letters[r-'a'], false, true
	case r >= 'A' && r <= 'Z':
		return letters[r-'A'], true, true
	case r >= '1' && r <= '9':
		return byte(0x02 + r - '1'), false, true
	case r == '0':
		return 0x0b, false, true
	case r == '-':
		return 0x0c, false, true
	}
	return 0, false, false
}

func TestUSScancodes(t *testing.T) {
	for r, want := range map[rune]byte{'a': 0x1e, 'q': 0x10, 'z': 0x2c, 'm': 0x32, 'O': 0x18, 'W': 0x11, '1': 0x02, '9': 0x0a, '0': 0x0b, '-': 0x0c} {
		if got, _, ok := usScancode(r); !ok || got != want {
			t.Errorf("%q: %#x, want %#x", r, got, want)
		}
	}
	if _, shift, _ := usScancode('O'); !shift {
		t.Error("an upper-case letter needs Shift")
	}
	if _, _, ok := usScancode('!'); ok {
		t.Error("a character outside the test passwords' was mapped")
	}
}

type reactivationRun struct {
	session     *CredSSPClientSession
	done        func()
	updates     chan RDPBitmapUpdate
	readErr     chan error
	framebuffer *RDPFramebuffer
	last        []byte
}

func openReactivationRun(address, pin, name string, roots *x509.CertPool, user, password string) (*reactivationRun, error) {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return nil, err
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	for _, step := range sequenceSteps(settings, user, password, "") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := step.run(ctx, session)
		cancel()
		if err != nil {
			done()
			return nil, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	caps := session.serverCapabilities
	framebuffer, err := NewRDPFramebuffer(caps.DesktopWidth, caps.DesktopHeight)
	if err != nil {
		done()
		return nil, err
	}
	r := &reactivationRun{session: session, done: done, updates: make(chan RDPBitmapUpdate, 16), readErr: make(chan error, 1), framebuffer: framebuffer}
	// The codec's reader, as the proxy runs it: a reactivation is followed inside ReadBitmapUpdate.
	go func() {
		for {
			update, err := session.ReadBitmapUpdate(context.Background(), 10*time.Minute)
			if err != nil {
				r.readErr <- err
				close(r.updates)
				return
			}
			r.updates <- update
		}
	}()
	return r, nil
}

// watch applies updates until none comes for quiet, or until limit; an error ends the stream.
func (r *reactivationRun) watch(quiet, limit time.Duration) error {
	end := time.After(limit)
	for {
		select {
		case update, ok := <-r.updates:
			if !ok {
				return <-r.readErr
			}
			if w, h := r.framebuffer.Dimensions(); update.DesktopWidth != 0 && (uint32(update.DesktopWidth) != w || uint32(update.DesktopHeight) != h) {
				if err := r.framebuffer.Resize(update.DesktopWidth, update.DesktopHeight); err != nil {
					return err
				}
			}
			if message, err := r.framebuffer.Apply(update, time.Now()); err == nil {
				r.last = message.PNG
			}
		case <-time.After(quiet):
			return nil
		case <-end:
			return nil
		}
	}
}

// typeText types text at a person's pace, Shift held for upper case, then Enter.
func (r *reactivationRun) typeText(text string) error {
	send := func(code byte, released bool) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		err := r.session.SendInput(ctx, []RDPInputEvent{{Type: RDPInputScancode, Scancode: code, Released: released}}, 10*time.Second)
		time.Sleep(50 * time.Millisecond)
		return err
	}
	for _, c := range text {
		code, shift, ok := usScancode(c)
		if !ok {
			return fmt.Errorf("no scancode for a character of the password")
		}
		if shift {
			if err := send(0x2a, false); err != nil {
				return err
			}
		}
		if err := send(code, false); err != nil {
			return err
		}
		if err := send(code, true); err != nil {
			return err
		}
		if shift {
			if err := send(0x2a, true); err != nil {
				return err
			}
		}
	}
	if err := send(0x1c, false); err != nil {
		return err
	}
	return send(0x1c, true)
}

func (r *reactivationRun) state() string {
	r.session.mu.Lock()
	defer r.session.mu.Unlock()
	return fmt.Sprintf("%d reactivation(s), logon notified %v, desktop %dx%d at %d bpp", r.session.reactivations, r.session.logonNotified,
		r.session.serverCapabilities.DesktopWidth, r.session.serverCapabilities.DesktopHeight, r.session.serverCapabilities.PreferredBitsPerPixel)
}

func TestRDPWindowsIsolation_Reactivation(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	if os.Getenv("RDP_WINDOWS_SESSION") != "prompt" {
		t.Skip("a target that always prompts for the password is needed (prepare.sh DIR 16 prompt)")
	}
	address, user, password := os.Getenv("RDP_WINDOWS_ADDRESS"), os.Getenv("RDP_WINDOWS_USER"), os.Getenv("RDP_WINDOWS_PASSWORD")
	pin, name := os.Getenv("RDP_WINDOWS_PIN"), os.Getenv("RDP_WINDOWS_SERVER_NAME")
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("RDP_WINDOWS_CA_FILE holds no certificate")
	}
	// No test before this one waits for the installation on this target: the pinned certificate,
	// which install.bat puts there at its very end, says it is over.
	wait := 90 * time.Minute
	if v, err := time.ParseDuration(os.Getenv("RDP_WINDOWS_WAIT")); err == nil {
		wait = v
	}
	for deadline := time.Now().Add(wait); ; {
		transport, err := DialHybrid(context.Background(), TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
		if err == nil {
			_ = transport.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target never presented the pinned certificate: %v", err)
		}
		time.Sleep(10 * time.Second)
	}
	// The ready task logs sessions off, then restarts Remote Desktop Services: let it settle.
	time.Sleep(30 * time.Second)
	dir := os.Getenv("RDP_WINDOWS_DUMP")
	var report []string
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report = append(report, line)
	}
	defer func() {
		if dir != "" {
			_ = os.WriteFile(filepath.Join(dir, "reactivation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
		}
	}()
	dump := func(file string, png []byte) {
		if dir != "" && png != nil {
			_ = os.WriteFile(filepath.Join(dir, file), png, 0o644)
		}
	}

	var reactivations [3]int
	for i := 1; i <= 2; i++ {
		run, err := openReactivationRun(address, pin, name, roots, user, password)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		if err := run.watch(8*time.Second, 90*time.Second); err != nil {
			run.done()
			t.Fatalf("connection %d, before the password: %v (%s)", i, err, run.state())
		}
		logf("connection %d, before the password: %s", i, run.state())
		dump(fmt.Sprintf("reactivation-%d-before.png", i), run.last)
		if err := run.typeText(password); err != nil {
			run.done()
			t.Fatalf("connection %d, typing: %v", i, err)
		}
		werr := run.watch(10*time.Second, 120*time.Second)
		logf("connection %d, after the password: %s; stream: %v", i, run.state(), werr)
		dump(fmt.Sprintf("reactivation-%d-after.png", i), run.last)
		run.session.mu.Lock()
		reactivations[i] = run.session.reactivations
		run.session.mu.Unlock()
		run.done() // the session stays on the target, disconnected
		if werr != nil {
			t.Fatalf("connection %d ended: %v", i, werr)
		}
		time.Sleep(5 * time.Second)
	}
	if reactivations[1]+reactivations[2] == 0 {
		t.Fatal("Windows sent no Deactivate All: moving to the disconnected session did not reactivate this connection")
	}
}

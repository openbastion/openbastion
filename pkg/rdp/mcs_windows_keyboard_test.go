package rdp

// ADR-0071, the Windows validation, the keyboard. CI run #41 opens a session on Windows' desktop,
// with Notepad. The screen test clicks into Notepad and types "o", "b", Enter: the click activates
// the window, the keys leave no text. This client sends CS_CORE keyboardLayout 0 ("the server
// chooses"); FreeRDP sends 0x409. Each case is a fresh connection with one layout: the session's
// stream until it settles, a click in the middle of the screen, a second, the keys, and the screen
// after, kept as a PNG to judge by eye.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_Keyboard -v

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestRDPWindowsIsolation_Keyboard(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
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
	var report []string
	for _, layout := range []uint32{0, 0x409} {
		line := fmt.Sprintf("keyboardLayout 0x%04x | %s", layout, keyboardRun(address, pin, name, roots, user, password, layout))
		t.Log(line)
		report = append(report, line)
		time.Sleep(3 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "keyboard-isolation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func keyboardRun(address, pin, name string, roots *x509.CertPool, user, password string, layout uint32) string {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return err.Error()
	}
	defer done()
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second, keyboardLayout: layout}
	steps := sequenceSteps(settings, user, password, "")
	for _, step := range steps {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		err := step.run(ctx, session)
		cancel()
		if err != nil {
			return fmt.Sprintf("%s: %v", step.name, err)
		}
	}
	caps := session.serverCapabilities
	framebuffer, err := NewRDPFramebuffer(caps.DesktopWidth, caps.DesktopHeight)
	if err != nil {
		return err.Error()
	}
	var last []byte
	frames := 0
	// The stream until it is quiet for quiet, or until limit. Read here, not by ReadBitmapUpdate:
	// a read that times out there ends the session, by design.
	conn := session.transport.Conn
	var assembler rdpFastPathAssembler
	watch := func(quiet, limit time.Duration) string {
		end := time.Now().Add(limit)
		for time.Now().Before(end) {
			_ = conn.SetReadDeadline(time.Now().Add(quiet))
			packet, err := readSlowOrFastPathPacket(conn)
			var netErr net.Error
			if errors.As(err, &netErr) && netErr.Timeout() {
				return ""
			}
			if err != nil {
				return err.Error()
			}
			if packet[0] == 3 {
				continue
			}
			update, err := reassembleFastPath(&assembler, packet, caps)
			if err != nil {
				return "refused: " + describeRDPServerPacket(packet)
			}
			if update == nil {
				continue
			}
			if message, err := framebuffer.Apply(*update, time.Now()); err == nil {
				last, frames = message.PNG, frames+1
			}
		}
		return ""
	}
	if problem := watch(8*time.Second, 60*time.Second); problem != "" {
		return fmt.Sprintf("before the keys, %d frames: %s", frames, problem)
	}
	before := frames
	x, y := caps.DesktopWidth/2, caps.DesktopHeight/2
	input := func(events ...RDPInputEvent) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return session.SendInput(ctx, events, 10*time.Second)
	}
	if err := input(RDPInputEvent{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1 | rdpPtrFlagsDown, X: x, Y: y},
		RDPInputEvent{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1, X: x, Y: y}); err != nil {
		return fmt.Sprintf("click: %v", err)
	}
	time.Sleep(time.Second)
	var keys []RDPInputEvent
	for _, code := range []byte{0x18, 0x30, 0x1c} { // o, b, Enter
		keys = append(keys, RDPInputEvent{Type: RDPInputScancode, Scancode: code}, RDPInputEvent{Type: RDPInputScancode, Scancode: code, Released: true})
	}
	if err := input(keys...); err != nil {
		return fmt.Sprintf("keys: %v", err)
	}
	problem := watch(5*time.Second, 20*time.Second)
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && last != nil {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("keyboard-0x%04x.png", layout)), last, 0o644)
	}
	return fmt.Sprintf("%d frames before the click, %d after; %s", before, frames-before, problem)
}

func TestRDPWindowsIsolation_KeyboardLayoutSeam(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: time.Second}
	want, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	settings.keyboardLayout = 0x409
	got, err := MarshalMCSConnectInitial(settings)
	if err != nil || len(got) != len(want) {
		t.Fatal(err)
	}
	diff := 0
	for i := range want {
		if got[i] != want[i] {
			diff++
		}
	}
	if diff != 2 || !strings.Contains(fmt.Sprintf("%x", got), "09040000") {
		t.Fatalf("%d bytes differ", diff)
	}
}

package rdp

// ADR-0071, the Windows validation, keys typed right after a click. CI runs #48 and #49 lost keys
// sent microseconds after the click that gave Notepad the focus; at a person's pace, none were lost.
// MS-RDPBCGR 2.2.8.1.1.3.1.1.5 recommends that a client gaining the focus send a Synchronize Event
// (and FreeRDP follows it with a Tab key-up). Does it change the loss?
//
// Each variant is a fresh connection to the same session (Notepad keeps its text across them), then
// three trials: a click on the desktop (Notepad loses the focus), a second, a click into Notepad,
// and at once three letters and Enter, one PDU per event, as the screen test sent them. Each variant
// types its own letter, so the last screen (a PNG to judge by eye) shows, line by line, what each
// trial kept:
//
//	A "aaa": no Synchronize Event;
//	B "bbb": one at activation, then a Tab key-up;
//	C "ccc": the same before each trial's click into Notepad.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_KeyAfterClick -v

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

type keyAfterClickVariant struct {
	name             string
	letter           byte // Set-1 make code
	syncAtActivation bool
	syncBeforeClick  bool
}

func keyAfterClickVariants() []keyAfterClickVariant {
	return []keyAfterClickVariant{
		{"A: no Synchronize Event", 0x1e, false, false},
		{"B: Synchronize Event at activation", 0x30, true, false},
		{"C: Synchronize Event before each click", 0x2e, false, true},
	}
}

// focusIn is what MS-RDPBCGR asks of a client that gains the focus: the toggle keys' state, then a
// Tab key-up, so that the server does not keep a key it believes held.
func focusIn() []RDPInputEvent {
	return []RDPInputEvent{{Type: RDPInputSync}, {Type: RDPInputScancode, Scancode: 0x0f, Released: true}}
}

func TestRDPWindowsIsolation_KeyAfterClick(t *testing.T) {
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
	for i, v := range keyAfterClickVariants() {
		line := fmt.Sprintf("%-42s | %s", v.name, keyAfterClickRun(address, pin, name, roots, user, password, v, i+1))
		t.Log(line)
		report = append(report, line)
		time.Sleep(3 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "key-after-click.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func keyAfterClickRun(address, pin, name string, roots *x509.CertPool, user, password string, v keyAfterClickVariant, index int) string {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return err.Error()
	}
	defer done()
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	for _, step := range sequenceSteps(settings, user, password, "") {
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
	conn := session.transport.Conn
	var last []byte
	// The stream until it is quiet; read here, as a read that times out in ReadBitmapUpdate ends
	// the session by design.
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
				last = message.PNG
			}
		}
		return ""
	}
	send := func(events ...RDPInputEvent) error {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		return session.SendInput(ctx, events, 10*time.Second)
	}
	if v.syncAtActivation {
		if err := send(focusIn()...); err != nil {
			return fmt.Sprintf("synchronize: %v", err)
		}
	}
	if problem := watch(8*time.Second, 60*time.Second); problem != "" {
		return "before the trials: " + problem
	}
	click := func(x, y uint16) error {
		if err := send(RDPInputEvent{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1 | rdpPtrFlagsDown, X: x, Y: y}); err != nil {
			return err
		}
		return send(RDPInputEvent{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1, X: x, Y: y})
	}
	for trial := 1; trial <= 3; trial++ {
		if err := click(1200, 300); err != nil { // the desktop, right of Notepad
			return fmt.Sprintf("trial %d, desktop click: %v", trial, err)
		}
		if problem := watch(time.Second, 3*time.Second); problem != "" {
			return fmt.Sprintf("trial %d: %s", trial, problem)
		}
		if v.syncBeforeClick {
			if err := send(focusIn()...); err != nil {
				return fmt.Sprintf("trial %d, synchronize: %v", trial, err)
			}
		}
		if err := click(caps.DesktopWidth/2, caps.DesktopHeight/2); err != nil { // into Notepad
			return fmt.Sprintf("trial %d, Notepad click: %v", trial, err)
		}
		// At once, one PDU per event, as the screen test of runs #48 and #49 sent them.
		for _, code := range []byte{v.letter, v.letter, v.letter, 0x1c} {
			for _, released := range []bool{false, true} {
				if err := send(RDPInputEvent{Type: RDPInputScancode, Scancode: code, Released: released}); err != nil {
					return fmt.Sprintf("trial %d, key: %v", trial, err)
				}
			}
		}
		if problem := watch(2*time.Second, 6*time.Second); problem != "" {
			return fmt.Sprintf("trial %d: %s", trial, problem)
		}
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && last != nil {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("key-after-click-%d.png", index)), last, 0o644)
	}
	return "three trials typed; judge the PNG"
}

func TestRDPWindowsIsolation_KeyAfterClickVariants(t *testing.T) {
	variants := keyAfterClickVariants()
	if variants[0].syncAtActivation || variants[0].syncBeforeClick {
		t.Fatal("variant A sends no Synchronize Event")
	}
	letters := map[byte]bool{}
	for _, v := range variants {
		letters[v.letter] = true
	}
	if len(letters) != len(variants) {
		t.Fatal("each variant types its own letter")
	}
	if _, err := marshalRDPInput(1007, 0x000103ea, focusIn()); err != nil {
		t.Fatalf("focus-in events: %v", err)
	}
}

package rdp

// ADR-0071, the Windows validation, reconnecting. A session this client opened, then left by
// closing its connection, stays on the target, disconnected; a new connection with the same
// credentials should take it back: Windows says the user's session opened (Save Session Info), with
// the same session ID, and the screen shows what was typed before.
//
// The first connection opens the session, waits for its screen to settle, clicks into Notepad and
// types "rr", Enter, at a person's pace, then closes. The second connection reads the logon
// notification and the screen, kept as a PNG (reconnect-after.png).
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_Reconnect -v

import (
	"context"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// logonSessionID reads the session ID of a Save Session Info logon notification: TS_LOGON_INFO
// (infoType 0, after the domain and user name fields) or TS_LOGON_INFO_VERSION_2 (infoType 1).
// -1 for any other packet, or a notification without one.
func logonSessionID(packet []byte) int64 {
	if len(packet) < 14 || packet[0] != 3 || packet[7] != mcsSendDataIndication {
		return -1
	}
	_, share, err := readPERLength(packet[13:])
	if err != nil || len(share) < 22 || binary.LittleEndian.Uint16(share[2:4])&0x0f != 7 || share[14] != 0x26 {
		return -1
	}
	switch binary.LittleEndian.Uint32(share[18:22]) {
	case 0: // cbDomain (4), Domain (52), cbUserName (4), UserName (512), SessionId
		if len(share) >= 22+572+4 {
			return int64(binary.LittleEndian.Uint32(share[22+572:]))
		}
	case 1: // Version (2), Size (4), SessionId
		if len(share) >= 22+6+4 {
			return int64(binary.LittleEndian.Uint32(share[22+6:]))
		}
	}
	return -1
}

type reconnectSession struct {
	session     *CredSSPClientSession
	done        func()
	framebuffer *RDPFramebuffer
	last        []byte
	sessionIDs  []int64
}

func openReconnectSession(address, pin, name string, roots *x509.CertPool, user, password string) (*reconnectSession, error) {
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
	return &reconnectSession{session: session, done: done, framebuffer: framebuffer}, nil
}

// watch reads the stream until it is quiet for quiet, or until limit, keeping the last screen and
// the logon notifications' session IDs. Read here: a read that times out in ReadBitmapUpdate ends
// the session by design.
func (r *reconnectSession) watch(quiet, limit time.Duration) error {
	conn, caps := r.session.transport.Conn, r.session.serverCapabilities
	end := time.Now().Add(limit)
	for time.Now().Before(end) {
		_ = conn.SetReadDeadline(time.Now().Add(quiet))
		packet, err := readSlowOrFastPathPacket(conn)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			return nil
		}
		if err != nil {
			return err
		}
		if packet[0] == 3 {
			if id := logonSessionID(packet); id >= 0 {
				r.sessionIDs = append(r.sessionIDs, id)
			} else if saveSessionInfo(packet) != "" {
				r.sessionIDs = append(r.sessionIDs, -1) // a logon notification without an ID
			}
			continue
		}
		if rdpFastPathUpdateIsIgnored(packet) {
			continue
		}
		update, err := parseRDPFastPathBitmapUpdateAt(packet, caps.DesktopWidth, caps.DesktopHeight, caps.PreferredBitsPerPixel)
		if err != nil {
			return errors.New("refused: " + describeRDPServerPacket(packet))
		}
		if message, err := r.framebuffer.Apply(update, time.Now()); err == nil {
			r.last = message.PNG
		}
	}
	return nil
}

func (r *reconnectSession) send(events ...RDPInputEvent) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return r.session.SendInput(ctx, events, 10*time.Second)
}

func TestRDPWindowsIsolation_Reconnect(t *testing.T) {
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
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report = append(report, line)
	}
	defer func() {
		if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, "reconnect.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
		}
	}()

	first, err := openReconnectSession(address, pin, name, roots, user, password)
	if err != nil {
		t.Fatalf("first connection: %v", err)
	}
	if err := first.watch(8*time.Second, 90*time.Second); err != nil {
		first.done()
		t.Fatalf("first connection, screen: %v", err)
	}
	caps := first.session.serverCapabilities
	x, y := caps.DesktopWidth/2, caps.DesktopHeight/2
	events := []RDPInputEvent{
		{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1 | rdpPtrFlagsDown, X: x, Y: y},
		{Type: RDPInputMouse, PointerFlags: rdpPtrFlagsButton1, X: x, Y: y},
	}
	for _, event := range events {
		if err := first.send(event); err != nil {
			first.done()
			t.Fatalf("click: %v", err)
		}
	}
	time.Sleep(time.Second)
	for _, code := range []byte{0x13, 0x13, 0x1c} { // r, r, Enter
		for _, released := range []bool{false, true} {
			if err := first.send(RDPInputEvent{Type: RDPInputScancode, Scancode: code, Released: released}); err != nil {
				first.done()
				t.Fatalf("keys: %v", err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}
	if err := first.watch(5*time.Second, 20*time.Second); err != nil {
		logf("first connection, after the keys: %v", err)
	}
	logf("first connection: logon notifications, session IDs %v", first.sessionIDs)
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && first.last != nil {
		_ = os.WriteFile(filepath.Join(dir, "reconnect-before.png"), first.last, 0o644)
	}
	first.done() // the session stays on the target, disconnected
	time.Sleep(5 * time.Second)

	second, err := openReconnectSession(address, pin, name, roots, user, password)
	if err != nil {
		t.Fatalf("second connection: %v", err)
	}
	defer second.done()
	if err := second.watch(8*time.Second, 90*time.Second); err != nil {
		t.Fatalf("second connection, screen: %v", err)
	}
	logf("second connection: logon notifications, session IDs %v", second.sessionIDs)
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && second.last != nil {
		_ = os.WriteFile(filepath.Join(dir, "reconnect-after.png"), second.last, 0o644)
	}
	if len(second.sessionIDs) == 0 {
		t.Fatal("the second connection got no logon notification: Windows did not hand the session back")
	}
	if len(first.sessionIDs) > 0 && first.sessionIDs[0] >= 0 && second.sessionIDs[0] >= 0 && first.sessionIDs[0] != second.sessionIDs[0] {
		t.Errorf("session %d, then %d: a new session, not the disconnected one", first.sessionIDs[0], second.sessionIDs[0])
	}
}

func TestRDPWindowsIsolation_LogonSessionID(t *testing.T) {
	packet := func(infoType uint32, data []byte) []byte {
		share := make([]byte, 22, 22+len(data))
		binary.LittleEndian.PutUint16(share[2:4], rdpShareDataPDU)
		share[14] = 0x26
		binary.LittleEndian.PutUint32(share[18:22], infoType)
		share = append(share, data...)
		binary.LittleEndian.PutUint16(share[0:2], uint16(len(share)))
		mcs := appendPERLength([]byte{mcsSendDataIndication, 0, 1, 0x03, 0xeb, 0x70}, len(share))
		mcs = append(mcs, share...)
		out := append([]byte{3, 0, 0, 0, 2, 0xf0, 0x80}, mcs...)
		binary.BigEndian.PutUint16(out[2:4], uint16(len(out)))
		return out
	}
	v1 := make([]byte, 576)
	binary.LittleEndian.PutUint32(v1[572:], 3)
	v2 := make([]byte, 10)
	binary.LittleEndian.PutUint32(v2[6:], 7)
	for _, c := range []struct {
		packet []byte
		want   int64
	}{{packet(0, v1), 3}, {packet(1, v2), 7}, {packet(2, nil), -1}, {packet(0, v1[:100]), -1}, {[]byte{0, 5, 1, 0, 0}, -1}} {
		if got := logonSessionID(c.packet); got != c.want {
			t.Errorf("session ID %d, want %d", got, c.want)
		}
	}
}

package rdp

// ADR-0071, the Windows validation, the logon. CI run #39 passes the whole workflow, but its
// screens show Windows' logon screen ("operator", an empty password box): the target did not open
// the session with the credentials this client sends, and the test's typing went into the password
// box. FreeRDP, on the same machine, gets a session. Its Client Info flags differ from this
// client's: no INFO_AUTOLOGON (it relies on the credentials CredSSP delegated), and
// INFO_DISABLECTRLALTDEL, INFO_LOGONNOTIFY, INFO_MOUSE, INFO_MAXIMIZESHELL, INFO_ENABLEWINDOWSKEY.
//
// Each case is a fresh connection with one set of flags, then 40 s of the server's stream: the
// Save Session Info PDUs it sends (a logon notification says the session opened) and the last
// screen, kept as a PNG to judge by eye. The cases run from the least to the most likely to open a
// session: once one has, the next ones may find it open, so the first that does is the answer.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation_Logon -v

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

const (
	rdpInfoMouse              = uint32(0x00000001)
	rdpInfoDisableCtrlAltDel  = uint32(0x00000002)
	rdpInfoMaximizeShell      = uint32(0x00000020)
	rdpInfoLogonNotify        = uint32(0x00000040)
	rdpInfoEnableWindowsKey   = uint32(0x00000100)
	rdpInfoClientDefaultFlags = rdpInfoUnicode | rdpInfoAutoLogon | rdpInfoForceEncryptedCSPDU
	freeRDPInfoFlags          = rdpInfoMouse | rdpInfoDisableCtrlAltDel | rdpInfoUnicode | rdpInfoMaximizeShell |
		rdpInfoLogonNotify | rdpInfoEnableWindowsKey | rdpInfoForceEncryptedCSPDU
)

type logonCase struct {
	name  string
	flags uint32
	// reactivate answers a Deactivate All as the specification asks (MS-RDPBCGR 1.3.1.3): the next
	// Demand Active, a Confirm Active, the finalization again.
	reactivate bool
}

func logonCases() []logonCase {
	// Run #40: with INFO_AUTOLOGON, whatever the other flags, Windows stays 40 s on its logon
	// screen; without it, as FreeRDP, the screen goes black and Windows closes after 5 frames,
	// which is what a logon that starts and a reactivation left unanswered look like.
	return []logonCase{
		{"this client's flags", rdpInfoClientDefaultFlags, true},
		{"FreeRDP's + AUTOLOGON, reactivation answered", freeRDPInfoFlags | rdpInfoAutoLogon, true},
		{"FreeRDP's (no AUTOLOGON), reactivation answered", freeRDPInfoFlags, true},
	}
}

func TestRDPWindowsIsolation_Logon(t *testing.T) {
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
	for i, c := range logonCases() {
		line := fmt.Sprintf("%-50s flags 0x%08x | %s", c.name, c.flags, logonRun(address, pin, name, roots, user, password, c, i+1))
		t.Log(line)
		report = append(report, line)
		time.Sleep(3 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "logon-isolation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func logonRun(address, pin, name string, roots *x509.CertPool, user, password string, c logonCase, index int) string {
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		return err.Error()
	}
	defer done()
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	timeout := 15 * time.Second
	steps := []sequenceStep{
		{"MCS", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ConnectMCS(ctx, settings)
			return err
		}},
		{"channels", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ConnectMCSChannels(ctx, timeout)
			return err
		}},
		{"Client Info", func(ctx context.Context, s *CredSSPClientSession) error {
			return s.SendClientInfo(ctx, RDPClientInfo{Username: user, Password: []byte(password), flags: c.flags}, timeout)
		}},
		{"licensing", func(ctx context.Context, s *CredSSPClientSession) error { return s.CompleteLicensing(ctx, timeout) }},
		{"capabilities", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ExchangeCapabilities(ctx, timeout)
			return err
		}},
		{"finalization", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.FinalizeConnection(ctx, timeout)
			return err
		}},
	}
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
	conn := session.transport.Conn
	deadline := time.Now().Add(40 * time.Second)
	var notes []string
	var last []byte
	frames := 0
	var assembler rdpFastPathAssembler
	for {
		_ = conn.SetReadDeadline(deadline)
		packet, err := readSlowOrFastPathPacket(conn)
		var netErr net.Error
		if errors.As(err, &netErr) && netErr.Timeout() {
			break
		}
		if err != nil {
			notes = append(notes, fmt.Sprintf("closed: %v", err))
			break
		}
		if packet[0] == 3 {
			if note := saveSessionInfo(packet); note != "" {
				notes = append(notes, note)
				continue
			}
			described := describeRDPServerPacket(packet)
			notes = append(notes, described)
			if c.reactivate && strings.Contains(described, "share PDU type 6") { // Deactivate All
				session.mu.Lock()
				session.capabilitiesExchanged, session.connectionFinalized = false, false
				session.mu.Unlock()
				ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				_, err := session.ExchangeCapabilities(ctx, timeout)
				if err == nil {
					_, err = session.FinalizeConnection(ctx, timeout)
				}
				cancel()
				if err != nil {
					notes = append(notes, fmt.Sprintf("reactivation: %v", err))
					break
				}
				notes = append(notes, "reactivated")
				caps = session.serverCapabilities
				if framebuffer, err = NewRDPFramebuffer(caps.DesktopWidth, caps.DesktopHeight); err != nil {
					notes = append(notes, err.Error())
					break
				}
			}
			continue
		}
		update, err := reassembleFastPath(&assembler, packet, caps)
		if err != nil {
			notes = append(notes, fmt.Sprintf("refused: %s", describeRDPServerPacket(packet)))
			break
		}
		if update == nil {
			continue
		}
		if message, err := framebuffer.Apply(*update, time.Now()); err == nil {
			last, frames = message.PNG, frames+1
		}
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" && last != nil {
		_ = os.WriteFile(filepath.Join(dir, fmt.Sprintf("logon-%d.png", index)), last, 0o644)
	}
	if len(notes) == 0 {
		notes = append(notes, "no Save Session Info")
	}
	return fmt.Sprintf("%d frames; %s", frames, strings.Join(notes, "; "))
}

// saveSessionInfo names a Save Session Info PDU (MS-RDPBCGR 2.2.10.1): its infoType, and for a
// LogonInfoV2 or extended info, that it is there. Empty for any other packet.
func saveSessionInfo(packet []byte) string {
	if len(packet) < 14 || packet[7] != mcsSendDataIndication {
		return ""
	}
	_, share, err := readPERLength(packet[13:])
	if err != nil || len(share) < 22 || binary.LittleEndian.Uint16(share[2:4])&0x0f != 7 || share[14] != 0x26 {
		return ""
	}
	names := map[uint32]string{0: "LOGON", 1: "LOGON_LONG", 2: "PLAIN_NOTIFY", 3: "LOGON_EXTENDED_INFO"}
	kind := binary.LittleEndian.Uint32(share[18:22])
	if n, ok := names[kind]; ok {
		return "Save Session Info " + n
	}
	return fmt.Sprintf("Save Session Info type %d", kind)
}

func TestRDPWindowsIsolation_LogonCases(t *testing.T) {
	cases := logonCases()
	if cases[0].flags != rdpInfoClientDefaultFlags || cases[2].flags&rdpInfoAutoLogon != 0 {
		t.Fatal("the first case must be the client as it is")
	}
	// The client's flags are what marshalRDPClientInfo sends when none are given.
	packet, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, RDPClientInfo{Username: "u", Password: []byte("p")})
	if err != nil {
		t.Fatal(err)
	}
	// TS_INFO_PACKET starts after TPKT (4), X.224 (3), MCS Send Data Request (8) and the basic
	// security header (4): codePage, then flags.
	if got := binary.LittleEndian.Uint32(packet[19+4 : 19+8]); got != rdpInfoClientDefaultFlags {
		t.Fatalf("default flags 0x%08x", got)
	}
	other, err := marshalRDPClientInfo(1007, mcsGlobalChannelID, RDPClientInfo{Username: "u", Password: []byte("p"), flags: freeRDPInfoFlags})
	if err != nil || binary.LittleEndian.Uint32(other[19+4:19+8]) != freeRDPInfoFlags {
		t.Fatalf("flags seam: %v", err)
	}
}

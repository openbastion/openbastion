package rdp

// ADR-0071, the Windows validation, after the Connect-Initial. CI run #27: with 15, 16, 24 and
// 32 bpp advertised, Windows answers this client's Connect-Initial with a Connect-Response this
// client accepts; the screen then fails 0.5 s later on a bare ErrMCSConnection, which every step
// after the Connect-Initial returns. This names the step, and shows what Windows sends after the
// Client Info PDU, before any step of this client reads it:
//
//   - the sequence as the RDP codec runs it, step by step, until one fails;
//   - on a second connection, the same steps through the finalization, then the server's next
//     packets as they come, described and unparsed (run #34 refused the first update after it).
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type sequenceStep struct {
	name string
	run  func(context.Context, *CredSSPClientSession) error
}

func sequenceSteps(settings MCSClientSettings, user, password string, through string) []sequenceStep {
	timeout := 15 * time.Second
	steps := []sequenceStep{
		{"MCS Connect-Initial/Response", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ConnectMCS(ctx, settings)
			return err
		}},
		{"Erect Domain, Attach User, Channel Joins", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ConnectMCSChannels(ctx, timeout)
			return err
		}},
		{"Client Info", func(ctx context.Context, s *CredSSPClientSession) error {
			return s.SendClientInfo(ctx, RDPClientInfo{Username: user, Password: []byte(password)}, timeout)
		}},
		{"Licensing", func(ctx context.Context, s *CredSSPClientSession) error { return s.CompleteLicensing(ctx, timeout) }},
		{"Demand Active/Confirm Active", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.ExchangeCapabilities(ctx, timeout)
			return err
		}},
		{"Finalization", func(ctx context.Context, s *CredSSPClientSession) error {
			_, err := s.FinalizeConnection(ctx, timeout)
			return err
		}},
	}
	for i, step := range steps {
		if step.name == through {
			return steps[:i+1]
		}
	}
	return steps
}

func TestRDPWindowsIsolation_ConnectionSequence(t *testing.T) {
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
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	var report []string
	logf := func(format string, args ...any) {
		line := fmt.Sprintf(format, args...)
		t.Log(line)
		report = append(report, line)
	}

	// The whole sequence, as the codec runs it.
	session, done, err := sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		logf("sequence: %v", err)
	} else {
		for _, step := range sequenceSteps(settings, user, password, "") {
			started := time.Now()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := step.run(ctx, session)
			cancel()
			if err != nil {
				logf("sequence: %-42s FAILED after %v: %v", step.name, time.Since(started).Round(time.Millisecond), err)
				break
			}
			logf("sequence: %-42s ok (%v)", step.name, time.Since(started).Round(time.Millisecond))
		}
		done()
	}
	time.Sleep(2 * time.Second)

	// Through the finalization, then what Windows sends, unread by any step: run #34, at 16 bpp,
	// opens the session and refuses the first update after it. Each packet is described (TPKT and
	// its Share Data type, or Fast-Path and each update's code, fragmentation and compression) with
	// its first bytes; nothing secret is in the graphics stream.
	session, done, err = sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		logf("after Finalization: %v", err)
	} else {
		ok := true
		for _, step := range sequenceSteps(settings, user, password, "Finalization") {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := step.run(ctx, session)
			cancel()
			if err != nil {
				logf("after Finalization: %s FAILED: %v", step.name, err)
				ok = false
				break
			}
		}
		if ok {
			conn := session.transport.Conn
			// Run #37: the codec shows five frames, then refuses an update. Every packet now goes
			// through the codec's own parsers, at the session's depth and size; those they accept are
			// counted, the first they refuse is described, kept in full, and ends the watch.
			caps := session.serverCapabilities
			deadline := time.Now().Add(30 * time.Second)
			ignored, decoded, slow := 0, 0, 0
			for i := 1; i <= 400; i++ {
				_ = conn.SetReadDeadline(deadline)
				packet, err := readSlowOrFastPathPacket(conn)
				var netErr net.Error
				if errors.As(err, &netErr) && netErr.Timeout() {
					logf("after Finalization: nothing refused in 30 s")
					break
				}
				if err != nil {
					logf("after Finalization: packet %d: %v", i, err)
					break
				}
				var parseErr error
				switch {
				case packet[0] != 3 && rdpFastPathUpdateIsIgnored(packet):
					ignored++
					continue
				case packet[0] != 3:
					_, parseErr = parseRDPFastPathBitmapUpdateAt(packet, caps.DesktopWidth, caps.DesktopHeight, caps.PreferredBitsPerPixel)
				default:
					slow++
					userData, segmentation, fragmentErr := parseRDPBitmapMCSFragment(packet, session.mcsResponse.IOChannelID)
					switch {
					case fragmentErr != nil:
						parseErr = fragmentErr
					case segmentation != 3:
						parseErr = fmt.Errorf("MCS segmentation %d", segmentation)
					case rdpShareDataIsIgnored(userData, caps.ShareID):
						ignored++
						continue
					default:
						_, _, parseErr = parseRDPBitmapShareDataAt(userData, caps.ShareID, caps.DesktopWidth, caps.DesktopHeight, caps.PreferredBitsPerPixel, rdpPrimaryOrderState{})
					}
				}
				if parseErr == nil {
					decoded++
					continue
				}
				head := packet
				if len(head) > 48 {
					head = head[:48]
				}
				logf("after Finalization: %d decoded, %d ignored, %d slow-path; packet %d REFUSED (%v), %d bytes, %s: %s",
					decoded, ignored, slow, i, parseErr, len(packet), describeServerPacket(packet), hex.EncodeToString(head))
				if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
					_ = os.WriteFile(filepath.Join(dir, "refused-update.bin"), packet, 0o644)
				}
				break
			}
			logf("after Finalization: %d decoded, %d ignored, %d slow-path", decoded, ignored, slow)
		}
		done()
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "connection-sequence.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

// sequenceSession dials and runs CredSSP. The transport closes when its dial context ends (run
// #28 lost both connections to a cancel on return): the context lives until the caller's done().
// readSlowOrFastPathPacket reads one TPKT packet (first byte 3) or one Fast-Path output packet
// (MS-RDPBCGR 2.2.9.1.2: action in the low bits, then a one- or two-byte length that counts the
// whole packet).
func readSlowOrFastPathPacket(r io.Reader) ([]byte, error) {
	var first [2]byte
	if _, err := io.ReadFull(r, first[:]); err != nil {
		return nil, err
	}
	if first[0] == 3 {
		return readTPKTPacket(io.MultiReader(bytes.NewReader(first[:]), r), 0xffff)
	}
	header := first[:]
	length := int(first[1])
	if first[1]&0x80 != 0 {
		var low [1]byte
		if _, err := io.ReadFull(r, low[:]); err != nil {
			return nil, err
		}
		header = append(header, low[0])
		length = int(first[1]&0x7f)<<8 | int(low[0])
	}
	if length < len(header) {
		return nil, fmt.Errorf("fast-path length %d", length)
	}
	packet := make([]byte, length)
	copy(packet, header)
	_, err := io.ReadFull(r, packet[len(header):])
	return packet, err
}

// describeServerPacket names what a server packet carries, without decoding its graphics.
func describeServerPacket(packet []byte) string {
	if len(packet) > 0 && packet[0] == 3 {
		if len(packet) < 14 || packet[7] != mcsSendDataIndication {
			return "TPKT"
		}
		_, share, err := readPERLength(packet[13:])
		if err != nil || len(share) < 6 {
			return "TPKT, MCS"
		}
		kind := binary.LittleEndian.Uint16(share[2:4]) & 0x0f
		if kind != 7 || len(share) < 20 {
			return fmt.Sprintf("TPKT, share PDU type %d", kind)
		}
		text := fmt.Sprintf("TPKT, share data pduType2 0x%02x", share[14])
		if share[14] == rdpPDU2Update {
			text += fmt.Sprintf(", update type %d", binary.LittleEndian.Uint16(share[18:20]))
		}
		return text
	}
	if len(packet) < 2 {
		return "?"
	}
	offset := 2
	if packet[1]&0x80 != 0 {
		offset = 3
	}
	var updates []string
	for rest := packet[offset:]; len(rest) >= 3; {
		header := rest[0]
		size := int(binary.LittleEndian.Uint16(rest[1:3]))
		body := 3
		if header>>6&0x2 != 0 { // compressed: one compressionFlags byte before the size
			if len(rest) < 4 {
				break
			}
			size = int(binary.LittleEndian.Uint16(rest[2:4]))
			body = 4
		}
		updates = append(updates, fmt.Sprintf("code %d frag %d comp %d size %d", header&0x0f, header>>4&0x3, header>>6, size))
		if body+size > len(rest) {
			updates = append(updates, "(truncated)")
			break
		}
		rest = rest[body+size:]
	}
	return fmt.Sprintf("Fast-Path action %d [%s]", packet[0]&0x3, strings.Join(updates, "; "))
}

func sequenceSession(address, pin, name string, roots *x509.CertPool, user, password string) (*CredSSPClientSession, func(), error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	transport, err := DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
	if err != nil {
		cancel()
		return nil, nil, fmt.Errorf("dial: %w", err)
	}
	session, err := transport.EstablishCredSSP(ctx, CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second})
	if err != nil {
		_ = transport.Close()
		cancel()
		return nil, nil, fmt.Errorf("CredSSP: %w", err)
	}
	return session, func() { session.Close(); cancel() }, nil
}

// The sequence is the codec's: the same steps, in the same order (engine/rdp.go).
func TestRDPWindowsIsolation_SequenceSteps(t *testing.T) {
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: time.Second}
	var names []string
	for _, step := range sequenceSteps(settings, "u", "p", "") {
		names = append(names, step.name)
	}
	want := "MCS Connect-Initial/Response|Erect Domain, Attach User, Channel Joins|Client Info|Licensing|Demand Active/Confirm Active|Finalization"
	if strings.Join(names, "|") != want {
		t.Fatalf("steps %q", names)
	}
	if n := len(sequenceSteps(settings, "u", "p", "Finalization")); n != 6 {
		t.Fatalf("through the finalization: %d steps", n)
	}
	// Two Fast-Path updates in one PDU are both named, with their fragmentation.
	two := []byte{0x00, 10, 0x21, 2, 0, 0xaa, 0xbb, 0x03, 0, 0}
	if got := describeServerPacket(two); got != "Fast-Path action 0 [code 1 frag 2 comp 0 size 2; code 3 frag 0 comp 0 size 0]" {
		t.Fatalf("%q", got)
	}
	// A Fast-Path header is read by its own length (one or two bytes), a TPKT by its own.
	for _, c := range []struct{ in, want []byte }{
		{[]byte{0x00, 0x05, 1, 2, 3, 9}, []byte{0x00, 0x05, 1, 2, 3}},
		{[]byte{0x00, 0x80, 0x06, 1, 2, 3}, []byte{0x00, 0x80, 0x06, 1, 2, 3}},
		{[]byte{3, 0, 0, 9, 2, 0xf0, 0x80, 1, 2, 9}, []byte{3, 0, 0, 9, 2, 0xf0, 0x80, 1, 2}},
	} {
		got, err := readSlowOrFastPathPacket(bytes.NewReader(c.in))
		if err != nil || !bytes.Equal(got, c.want) {
			t.Fatalf("% x: % x, %v", c.in, got, err)
		}
	}
}

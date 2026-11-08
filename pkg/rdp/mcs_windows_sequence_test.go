package rdp

// ADR-0071, the Windows validation, after the Connect-Initial. CI run #27: with 15, 16, 24 and
// 32 bpp advertised, Windows answers this client's Connect-Initial with a Connect-Response this
// client accepts; the screen then fails 0.5 s later on a bare ErrMCSConnection, which every step
// after the Connect-Initial returns. This names the step, and shows what Windows sends after the
// Client Info PDU, before any step of this client reads it:
//
//   - the sequence as the RDP codec runs it, step by step, until one fails;
//   - on a second connection, the same steps through the capability exchange, then the server's
//     next packets as they come, unparsed (run #30 named the finalization).
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"bytes"
	"context"
	"crypto/x509"
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

	// Through the capability exchange, then what Windows sends, unread by any step: run #30, with
	// 32 bpp allowed on the target, passes the capability exchange and names the finalization. The
	// packets come in full (finalization PDUs, nothing secret), TPKT or Fast-Path alike.
	session, done, err = sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		logf("after Confirm Active: %v", err)
	} else {
		ok := true
		for _, step := range sequenceSteps(settings, user, password, "Demand Active/Confirm Active") {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := step.run(ctx, session)
			cancel()
			if err != nil {
				logf("after Confirm Active: %s FAILED: %v", step.name, err)
				ok = false
				break
			}
		}
		if ok {
			conn := session.transport.Conn
			deadline := time.Now().Add(6 * time.Second)
			for i := 0; i < 8; i++ {
				_ = conn.SetReadDeadline(deadline)
				packet, err := readSlowOrFastPathPacket(conn)
				var netErr net.Error
				switch {
				case errors.As(err, &netErr) && netErr.Timeout():
					logf("after Confirm Active: nothing more in 6 s")
				case err != nil:
					logf("after Confirm Active: packet %d: %v", i+1, err)
				default:
					head := packet
					if len(head) > 4096 {
						head = head[:4096]
					}
					logf("after Confirm Active: packet %d, %d bytes: %s", i+1, len(packet), hex.EncodeToString(head))
					continue
				}
				break
			}
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
	if n := len(sequenceSteps(settings, "u", "p", "Demand Active/Confirm Active")); n != 5 {
		t.Fatalf("through the capability exchange: %d steps", n)
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

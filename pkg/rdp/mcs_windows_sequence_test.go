package rdp

// ADR-0071, the Windows validation, after the Connect-Initial. CI run #27: with 15, 16, 24 and
// 32 bpp advertised, Windows answers this client's Connect-Initial with a Connect-Response this
// client accepts; the screen then fails 0.5 s later on a bare ErrMCSConnection, which every step
// after the Connect-Initial returns. This names the step, and shows what Windows sends after the
// Client Info PDU, before any step of this client reads it:
//
//   - the sequence as the RDP codec runs it, step by step, until one fails;
//   - on a second connection, the same steps up to Client Info, then the server's next packets as
//     they come (TPKT length and first bytes), unparsed.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"context"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
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
	session, err := sequenceSession(address, pin, name, roots, user, password)
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
		session.Close()
	}
	time.Sleep(2 * time.Second)

	// Up to Client Info, then what Windows sends, unread by any step.
	session, err = sequenceSession(address, pin, name, roots, user, password)
	if err != nil {
		logf("after Client Info: %v", err)
	} else {
		ok := true
		for _, step := range sequenceSteps(settings, user, password, "Client Info") {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			err := step.run(ctx, session)
			cancel()
			if err != nil {
				logf("after Client Info: %s FAILED: %v", step.name, err)
				ok = false
				break
			}
		}
		if ok {
			conn := session.transport.Conn
			deadline := time.Now().Add(6 * time.Second)
			for i := 0; i < 8; i++ {
				_ = conn.SetReadDeadline(deadline)
				packet, err := readTPKTPacket(conn, 0xffff)
				var netErr net.Error
				switch {
				case errors.As(err, &netErr) && netErr.Timeout():
					logf("after Client Info: nothing more in 6 s")
				case err != nil:
					logf("after Client Info: packet %d: %v", i+1, err)
				default:
					head := packet
					if len(head) > 96 {
						head = head[:96]
					}
					logf("after Client Info: packet %d, %d bytes: %s", i+1, len(packet), hex.EncodeToString(head))
					continue
				}
				break
			}
		}
		session.Close()
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "connection-sequence.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

func sequenceSession(address, pin, name string, roots *x509.CertPool, user, password string) (*CredSSPClientSession, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport, err := DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	session, err := transport.EstablishCredSSP(ctx, CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second})
	if err != nil {
		_ = transport.Close()
		return nil, fmt.Errorf("CredSSP: %w", err)
	}
	return session, nil
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
	if n := len(sequenceSteps(settings, "u", "p", "Client Info")); n != 3 {
		t.Fatalf("through Client Info: %d steps", n)
	}
}

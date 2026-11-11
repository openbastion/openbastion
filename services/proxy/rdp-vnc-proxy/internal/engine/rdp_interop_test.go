package engine

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"image"
	"image/png"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

// A real RDP server, FreeRDP 3 (test/integration/testdata/rdp/freerdp, ADR-0071): every byte of this
// client's protocol stack has only ever met fakes written from the same reading of the specification
// until this test, and they shared its mistakes. Not Windows: that criterion stays open.
//
//	make test-rdp-interop
type rdpInteropTarget struct {
	address, container, pin string
	roots                   *x509.CertPool
}

const (
	rdpInteropUser     = "operator"
	rdpInteropPassword = "Demo-RDP-Pass1"
	rdpInteropName     = "rdp-target"
)

// startRDPInteropTarget starts FreeRDP's shadow server; env adds to its container's environment
// (RDP_DISPLAY=resizable: Xvnc, which also gives the shadow server a pointer to send).
func startRDPInteropTarget(t *testing.T, env ...string) rdpInteropTarget {
	t.Helper()
	if os.Getenv("RDP_INTEROP") == "" {
		t.Skip("RDP_INTEROP not set: this test builds and starts a real RDP server in Docker")
	}
	_, here, _, _ := runtime.Caller(0)
	context := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "..", "test", "integration", "testdata", "rdp", "freerdp")
	const image = "openbastion-test-freerdp:latest"
	if out, err := exec.Command("docker", "build", "-q", "-t", image, context).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	container := fmt.Sprintf("ob-rdp-interop-%d", os.Getpid())
	args := []string{"run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::3389",
		"-e", "RDP_USER=" + rdpInteropUser, "-e", "RDP_PASSWORD=" + rdpInteropPassword}
	for _, variable := range env {
		args = append(args, "-e", variable)
	}
	if out, err := exec.Command("docker", append(args, image)...).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	port, err := exec.Command("docker", "port", container, "3389/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	target := rdpInteropTarget{address: strings.TrimSpace(strings.Split(string(port), "\n")[0]), container: container}
	deadline := time.Now().Add(30 * time.Second)
	for {
		// The certificate, once the server listens (0D3D is 3389 in /proc/net/tcp).
		raw, err := exec.Command("docker", "exec", container, "sh", "-c", "grep -qs :0D3D /proc/net/tcp /proc/net/tcp6 && cat ~/.config/freerdp/shadow/shadow.crt").Output()
		logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
		if block, _ := pem.Decode(raw); err == nil && block != nil {
			sum := sha256.Sum256(block.Bytes)
			target.pin = hex.EncodeToString(sum[:])
			target.roots = x509.NewCertPool()
			target.roots.AppendCertsFromPEM(raw)
			return target
		}
		if time.Now().After(deadline) {
			t.Fatalf("the target did not start: %s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func (r rdpInteropTarget) logs(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("docker", "logs", r.container).CombinedOutput()
	if err != nil {
		t.Fatalf("docker logs: %v", err)
	}
	return string(out)
}

func (r rdpInteropTarget) authenticate(ctx context.Context, password string) (*rdp.CredSSPClientSession, error) {
	transport, err := rdp.DialHybrid(ctx, rdp.TransportConfig{
		Address: r.address, TLSFingerprint: r.pin, TLSRoots: r.roots, TLSServerName: rdpInteropName, DialTimeout: 10 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	session, err := transport.EstablishCredSSP(ctx, rdp.CredSSPClientConfig{
		Version: 6, Username: rdpInteropUser, Password: []byte(password), Timeout: 10 * time.Second,
	})
	if err != nil {
		_ = transport.Close()
		return nil, err
	}
	return session, nil
}

func TestRDPInterop_CredSSP(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	t.Run("the server accepts the proof, and this client the server's", func(t *testing.T) {
		session, err := target.authenticate(ctx, rdpInteropPassword)
		if err != nil {
			t.Fatalf("%v\n%s", err, target.logs(t))
		}
		session.Close()
	})
	t.Run("a wrong password authenticates nothing", func(t *testing.T) {
		if session, err := target.authenticate(ctx, "not-the-password"); err == nil {
			session.Close()
			t.Fatal("authenticated with a wrong password")
		}
		if logs := target.logs(t); !strings.Contains(logs, "MESSAGE_ALTERED") && !strings.Contains(logs, "LOGON_FAILURE") {
			t.Fatalf("the server did not refuse the proof: nothing above says why it failed\n%s", logs)
		}
	})
	t.Run("an impostor's pin stops before any CredSSP byte", func(t *testing.T) {
		before := target.logs(t)
		other := target
		other.pin = strings.Repeat("0", 64)
		_, err := other.authenticate(ctx, rdpInteropPassword)
		if !errors.Is(err, rdp.ErrTLSVerification) {
			t.Fatalf("%v", err)
		}
		time.Sleep(time.Second)
		if logs := target.logs(t)[len(before):]; strings.Contains(logs, "NTLM") || strings.Contains(logs, "AcceptSecurityContext") {
			t.Fatalf("the target received CredSSP: %s", logs)
		}
	})
}

// The pointer drawn into the frames (ADR-0091), against FreeRDP, on Xvnc as the recording test.
func TestRDPInterop_Pointer(t *testing.T) {
	target := startRDPInteropTarget(t, "RDP_DISPLAY=resizable")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 10 * time.Second, DrawPointer: true}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	defer session.Close()
	provePointerIsDrawn(t, session, false, func(name string, frame screenstream.Message) {
		if dir := os.Getenv("RDP_INTEROP_DUMP"); dir != "" {
			_ = os.WriteFile(filepath.Join(dir, name), frame.PNG, 0o600)
		}
	})
}

// The measurements of ADR-0090 (lot A) against FreeRDP: the harness Windows runs, on scenes a
// terminal running `cat` can show.
func TestRDPInterop_Measure(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 10 * time.Second, DrawPointer: true,
		FrameInterval: 50 * time.Millisecond}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	defer session.Close()
	m := newSessionMeter(t, "freerdp", session, rdpServerBytes(t, session))
	m.settle(3*time.Second, 30*time.Second)
	// No window manager: the keyboard goes to the window under the pointer, xterm at the top left.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 100, Y: 100}); err != nil {
		t.Fatal(err)
	}
	m.settle(time.Second, 10*time.Second)
	m.scene("idle", func() { time.Sleep(5 * time.Second) })
	m.latency("key-to-frame", 10, func() { rdpKeys(t, session, 0, 0x1e) }, func() { rdpKeys(t, session, 0, 0x0e) })
	m.scene("typing", func() { rdpKeys(t, session, 30*time.Millisecond, rdpSentence...) })
	m.scene("scrolling", func() {
		for i := 0; i < 40; i++ {
			rdpKeys(t, session, 50*time.Millisecond, 0x1c)
		}
	})
	m.scene("pointer", func() { m.pointerCircle(640, 400, 150, 50, 20*time.Millisecond) })
	m.publish(os.Getenv("RDP_INTEROP_DUMP"))
}

func TestRDPInterop_Screen(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	codec := &RDPCodec{TLSRoots: target.roots, DialTimeout: 10 * time.Second}
	session, err := codec.Open(ctx, cred)
	if err != nil {
		var failure *proxycore.ScreenFailure
		if errors.As(err, &failure) {
			t.Fatalf("%v: %v\n%s", err, failure.Err, target.logs(t))
		}
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	defer session.Close()

	next := func(limit time.Duration) (screenstream.Message, bool) {
		select {
		case message, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended: %v\n%s", session.Err(), target.logs(t))
			}
			return message, true
		case <-time.After(limit):
			return screenstream.Message{}, false
		}
	}
	// The first screen comes in slices of rectangles: only a quiet screen can show what a key did.
	settle := func(frame screenstream.Message) screenstream.Message {
		for {
			following, ok := next(3 * time.Second)
			if !ok {
				return frame
			}
			frame = following
		}
	}
	first, ok := next(20 * time.Second)
	if !ok {
		t.Fatalf("no frame in 20 s: %v\n%s", session.Err(), target.logs(t))
	}
	before := settle(first)
	if len(before.PNG) == 0 || before.Width != 1280 || before.Height != 800 {
		t.Fatalf("frame: %d bytes, %dx%d", len(before.PNG), before.Width, before.Height)
	}
	dump := func(name string, frame screenstream.Message) {
		if dir := os.Getenv("RDP_INTEROP_DUMP"); dir != "" {
			if err := os.WriteFile(filepath.Join(dir, name), frame.PNG, 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	dump("before.png", before)
	shown := rdpInteropDecode(t, before)
	if !rdpInteropIs(shown, 100, 100, 0xff) || !rdpInteropIs(shown, 800, 600, 0) {
		t.Fatalf("not the target's screen, an xterm on black: %v at (100,100), %v at (800,600)", shown.At(100, 100), shown.At(800, 600))
	}
	// No window manager on this X server: the keyboard goes to the window under the pointer.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 100, Y: 100}); err != nil {
		t.Fatalf("pointer: %v", err)
	}
	// xterm runs `cat`: what is typed shows only if the key reached the desktop.
	for _, scancode := range []uint16{0x1e, 0x30, 0x1c} { // a, b, Enter
		for _, flags := range []uint8{screenstream.KeyPressed, screenstream.KeyReleased} {
			if err := session.Input(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: scancode, Flags: flags}); err != nil {
				t.Fatalf("input: %v", err)
			}
		}
	}
	changed, ok := next(10 * time.Second)
	if !ok {
		t.Fatalf("the screen did not change after the keys: %v\n%s", session.Err(), target.logs(t))
	}
	after := settle(changed)
	dump("after.png", after)
	if bytes.Equal(after.PNG, before.PNG) {
		t.Fatal("the screen came back identical: the keys changed nothing")
	}
	// Only where xterm writes: the first lines of its window, not anywhere on the desktop.
	typed := rdpInteropDecode(t, after)
	for y := 0; y < 800; y++ {
		for x := 0; x < 1280; x++ {
			if typed.At(x, y) != shown.At(x, y) && (x > 484 || y > 60) {
				t.Fatalf("a change outside the terminal's first lines at (%d,%d)", x, y)
			}
		}
	}
}

func rdpInteropDecode(t *testing.T, frame screenstream.Message) image.Image {
	t.Helper()
	decoded, err := png.Decode(bytes.NewReader(frame.PNG))
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func rdpInteropIs(shown image.Image, x, y int, value uint32) bool {
	r, g, b, a := shown.At(x, y).RGBA()
	return r>>8 == value && g>>8 == value && b>>8 == value && a>>8 == 0xff
}

// The reactivation (MS-RDPBCGR 1.3.1.3), against a real server: FreeRDP's shadow server keeps the
// size of its screen, 1280x800. A client that asks for another gets, once connected, a Deactivate
// All, then a Demand Active of the server's size, and must go through the capabilities and the
// finalization again. The operator then sees the server's screen at the server's size.
func TestRDPInterop_Reactivation(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	codec := &RDPCodec{TLSRoots: target.roots, DialTimeout: 10 * time.Second, DesktopWidth: 1024, DesktopHeight: 768}
	session, err := codec.Open(ctx, cred)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	defer session.Close()
	var last screenstream.Message
	for frames := 0; ; frames++ {
		select {
		case message, ok := <-session.Frames():
			if !ok {
				t.Fatalf("the stream ended after %d frame(s): %v\n%s", frames, session.Err(), target.logs(t))
			}
			last = message
			continue
		case <-time.After(3 * time.Second):
		}
		if frames == 0 {
			t.Fatalf("no frame: %v\n%s", session.Err(), target.logs(t))
		}
		break
	}
	if last.Width != 1280 || last.Height != 800 {
		t.Fatalf("last frame %dx%d, not the server's 1280x800", last.Width, last.Height)
	}
	shown := rdpInteropDecode(t, last)
	if !rdpInteropIs(shown, 100, 100, 0xff) || !rdpInteropIs(shown, 1200, 700, 0) {
		t.Fatalf("not the target's screen, an xterm on black: %v at (100,100), %v at (1200,700)", shown.At(100, 100), shown.At(1200, 700))
	}
	// Input at the new size: a point the old size had not.
	if err := session.Input(screenstream.InputEvent{Type: screenstream.InputPointer, X: 1200, Y: 700}); err != nil {
		t.Fatalf("pointer at the server's size: %v", err)
	}
}

// A target that dies is not a session that ended (ADR-0071 §3, "Fin"), against a real server:
// FreeRDP's shadow server is killed mid-session (its container: PID 1 ignores SIGTERM). The stream
// ends with an error, which the relay says as target_unreachable, never as session_ended: only a
// Disconnect Provider Ultimatum is an end (pkg/rdp, and Windows' logoff in CI).
func TestRDPInterop_AServerThatDiesIsNoEndOfSession(t *testing.T) {
	target := startRDPInteropTarget(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(rdpInteropPassword), TargetHost: target.address,
		TargetUser: rdpInteropUser, TLSCertificateSHA256: target.pin, TargetDomain: rdpInteropName,
	}}, "rdp-vnc-proxy").Fetch(ctx, "one-use")
	if err != nil {
		t.Fatal(err)
	}
	session, err := (&RDPCodec{TLSRoots: target.roots, DialTimeout: 10 * time.Second}).Open(ctx, cred)
	if err != nil {
		t.Fatalf("%v\n%s", err, target.logs(t))
	}
	defer session.Close()
	select {
	case _, ok := <-session.Frames():
		if !ok {
			t.Fatalf("no frame: %v", session.Err())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("no frame in 20 s")
	}
	if out, err := exec.Command("docker", "kill", target.container).CombinedOutput(); err != nil {
		t.Fatalf("stopping the server: %v\n%s", err, out)
	}
	for deadline := time.After(30 * time.Second); ; {
		select {
		case _, ok := <-session.Frames():
			if ok {
				continue
			}
			if err := session.Err(); err == nil || errors.Is(err, rdp.ErrSessionEnded) {
				t.Fatalf("a dead server was taken for a session that ended: %v", err)
			}
			return
		case <-deadline:
			t.Fatal("the stream did not end after the server stopped")
		}
	}
}

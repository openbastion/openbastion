package interfaces

// ADR-0071, the recording of an RDP session, end to end: the proxy's real HTTP server and screen
// relay with the RDP codec, a real RDP server (FreeRDP 3, in Docker), and
// the real Video Recorder as its own process, on PostgreSQL, over mutual TLS. The ticket is
// registered here, as the Broker would: the operator's route from the public API is
// test/integration's TestScreenFlow_RDPFrom… (ADR-0088). Around the recorder, what VNC's flow (test/integration) also
// stands in for: the object store, the audit service and the authorization's answer.
//
// The claims: every frame the operator saw is, to the byte, the frame an auditor replays under
// the same sequence; the recording is contiguous and sealed when the operator leaves; it follows a
// reactivation that changes the desktop's size (the client asks for 1024x768, FreeRDP's server
// shows 1280x800); a reader without the right gets nothing, and every read is audited.
//
//	RDP_INTEROP=1 TEST_DATABASE_URL=… go test ./services/proxy/rdp-vnc-proxy/internal/interfaces -run TestRDPRecording -v

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"image/png"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/engine"
	"github.com/openbastion/openbastion/services/proxy/rdp-vnc-proxy/internal/infrastructure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

const (
	recordingTrustDomain = "it.openbastion"
	recordingRDPUser     = "operator"
	recordingRDPPassword = "Demo-RDP-Pass1"
	recordingRDPName     = "rdp-target"
)

func TestRDPRecording_WhatTheOperatorSawIsWhatAnAuditorReplays(t *testing.T) {
	windows := os.Getenv("RDP_WINDOWS") != ""
	if os.Getenv("RDP_INTEROP") == "" && !windows {
		t.Skip("RDP_INTEROP (FreeRDP in Docker) or RDP_WINDOWS (a Windows target, test.env) is needed")
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set: the Video Recorder needs PostgreSQL")
	}
	_, here, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(here), "..", "..", "..", "..", "..")
	var target recordingRDPTarget
	if windows {
		target = recordingWindowsTarget(t)
	} else {
		target = startRecordingRDPTarget(t, root)
	}

	// The deployment's identities, as make pki makes them.
	pkiDir := t.TempDir()
	ca, err := pki.InitDir(pkiDir, recordingTrustDomain, 24*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	for _, service := range []string{mtls.VideoRecorder, mtls.RDPVNCProxy, mtls.APIGateway, mtls.Authorization, mtls.AuditService} {
		if _, err := pki.IssueToDir(ca, pkiDir, service, pki.IssueOptions{TTL: time.Hour}); err != nil {
			t.Fatal(err)
		}
	}
	identity := func(service string) *mtls.Runtime {
		rt, err := mtls.SetupWith(service, mtls.Settings{Mode: mtls.Required, TrustDomain: recordingTrustDomain,
			CertFile: pki.CertFile(pkiDir, service), KeyFile: pki.KeyFile(pkiDir, service), CAFile: pki.CAFile(pkiDir)})
		if err != nil {
			t.Fatal(err)
		}
		return rt
	}

	// What stands around the recorder: an object store, the audit service, the authorization.
	store := newRecordingObjectStore(t)
	audit := &recordingAuditSpy{}
	auditURL := serveAs(t, identity(mtls.AuditService), http.MethodPost, "/audit/v1/emit-event", audit.ServeHTTP)
	// Only an auditor reads a recording (the policy VNC's flow creates: recording:session:*).
	authzURL := serveAs(t, identity(mtls.Authorization), http.MethodPost, "/authz/v1/check-access", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			ActorRoles []string `json:"actor_roles"`
			Resource   string   `json:"resource"`
			Action     string   `json:"action"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		allowed := strings.HasPrefix(req.Resource, "recording:session:") && req.Action == "recording:session:read" && contains(req.ActorRoles, "session-auditor")
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed, "decision_reason": "test policy"})
	})

	httpPort, grpcPort := freePort(t), freePort(t)
	recorderURL := "https://127.0.0.1:" + grpcPort
	video := startVideoRecorder(t, root, pkiDir, httpPort, grpcPort, dsn, store.URL, authzURL, auditURL)

	// The proxy, as cmd/rdp-vnc-proxy builds it.
	recorder, err := infrastructure.NewVideoRecorderClient(identity(mtls.RDPVNCProxy), recorderURL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = recorder.Close() })
	waitFor(t, 60*time.Second, "the Video Recorder to be ready", video, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		return recorder.Ready(ctx) == nil
	})
	vault := recordingVault{fetched: proxycore.Fetched{
		Type: "password", Material: []byte(target.password), TargetHost: target.address,
		TargetUser: target.user, TLSCertificateSHA256: target.pin, TargetDomain: target.name,
	}}
	listener := proxycore.NewListener(proxycore.NewCredentialFetcher(vault, mtls.RDPVNCProxy), proxycore.NewTerminator(noopAudit{}))
	// The pointer drawn, as SCREEN_DRAW_POINTER is by default (ADR-0091): recorded as shown.
	codec := &engine.RDPCodec{TLSRoots: target.roots, DialTimeout: 15 * time.Second, DesktopWidth: target.askWidth, DesktopHeight: target.askHeight,
		DrawPointer: true}
	// As cmd/rdp-vnc-proxy builds it with RDP_ENABLED=true (ADR-0088): VNC's codec, and RDP's for an
	// RDP ticket.
	server := NewHTTPServer(infrastructure.NewPendingScreenSessions(), listener, &engine.VNCCodec{TLSRoots: target.roots}, recorder, "rdp-vnc-proxy:8090", nil).WithRDP(codec)
	proxy := httptest.NewServer(server.Routes())
	t.Cleanup(proxy.Close)

	// What the Broker would have done for an RDP account: a one-use ticket for this session.
	suffix := make([]byte, 6)
	_, _ = rand.Read(suffix)
	sessionID := "rdp-recording-" + hex.EncodeToString(suffix)
	ticket, err := server.pending.Register(infrastructure.PendingScreenSession{SessionID: sessionID, ScopeToken: "scope-of-" + sessionID,
		Protocol: screenstream.ProtocolRDP, ExpiresAt: time.Now().UTC().Add(5 * time.Minute)})
	if err != nil {
		t.Fatal(err)
	}

	// The operator.
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Minute)
	defer cancel()
	conn, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(proxy.URL, "http")+"/internal/v1/screen", &websocket.DialOptions{
		Subprotocols: []string{screenSubprotocol}, HTTPHeader: http.Header{"Authorization": {"Bearer " + ticket}},
	})
	if err != nil {
		t.Fatal(err)
	}
	conn.SetReadLimit(8 << 20)
	// A read cancelled by its context closes a WebSocket: one reader, and a channel to wait on.
	messages := make(chan []byte, 64)
	readErr := make(chan error, 1)
	go func() {
		for {
			_, data, err := conn.Read(ctx)
			if err != nil {
				readErr <- err
				close(messages)
				return
			}
			messages <- data
		}
	}()
	shown := map[uint64]screenstream.Message{}
	var last screenstream.Message
	read := func(quiet time.Duration) {
		for {
			var data []byte
			select {
			case got, ok := <-messages:
				if !ok {
					t.Fatalf("the screen closed: %v\n%s", <-readErr, video.out.String())
				}
				data = got
			case <-time.After(quiet):
				return
			}
			m, err := screenstream.Decode(data)
			if err != nil {
				t.Fatalf("decode: %v", err)
			}
			switch m.Type {
			case screenstream.TypeHello:
				if m.Protocol != screenstream.ProtocolRDP || m.SessionID != sessionID {
					t.Fatalf("HELLO %+v", m)
				}
			case screenstream.TypeEnd:
				t.Fatalf("END %d %q\n%s", m.EndCode, m.Text, video.out.String())
			case screenstream.TypeFrame:
				shown[m.Sequence], last = m, m
			}
		}
	}
	send := func(e screenstream.InputEvent) {
		data, err := screenstream.EncodeInput(e)
		if err != nil {
			t.Fatal(err)
		}
		if err := conn.Write(ctx, websocket.MessageBinary, data); err != nil {
			t.Fatal(err)
		}
	}
	key := func(scancode uint16) {
		send(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: scancode, Flags: screenstream.KeyPressed})
		time.Sleep(target.keyPace)
		send(screenstream.InputEvent{Type: screenstream.InputKey, Scancode: scancode, Flags: screenstream.KeyReleased})
		time.Sleep(target.keyPace)
	}
	if windows {
		// Windows' desktop, then Notepad, which may appear more than 10 s after it (rdp-setup.ps1).
		for deadline := time.Now().Add(90 * time.Second); len(shown) == 0; {
			if time.Now().After(deadline) {
				t.Fatal("no frame from Windows in 90 s")
			}
			read(2 * time.Second)
		}
		read(10 * time.Second)
		read(10 * time.Second)
		if len(shown) == 0 || last.Width != 1280 || last.Height != 800 {
			t.Fatalf("%d frame(s), the last %dx%d: not the 1280x800 asked for", len(shown), last.Width, last.Height)
		}
		before := last
		// Into Notepad, then o, b, Enter at a person's pace (the screen test's, ADR-0071).
		send(screenstream.InputEvent{Type: screenstream.InputPointer, X: 640, Y: 400, Buttons: 1})
		send(screenstream.InputEvent{Type: screenstream.InputPointer, X: 640, Y: 400})
		time.Sleep(time.Second)
		for _, scancode := range []uint16{0x18, 0x30, 0x1c} {
			key(scancode)
		}
		read(8 * time.Second)
		if bytes.Equal(last.PNG, before.PNG) {
			t.Fatal("the keys changed nothing on the screen")
		}
	} else {
		read(5 * time.Second)
		if len(shown) == 0 || last.Width != 1280 || last.Height != 800 {
			t.Fatalf("%d frame(s), the last %dx%d: not the server's 1280x800", len(shown), last.Width, last.Height)
		}
		before := last
		// xterm runs `cat`: the keys show only if they reached the desktop. No window manager:
		// the keyboard goes to the window under the pointer.
		send(screenstream.InputEvent{Type: screenstream.InputPointer, X: 100, Y: 100})
		for _, scancode := range []uint16{0x1e, 0x30, 0x1c} { // a, b, Enter
			key(scancode)
		}
		read(3 * time.Second)
		if bytes.Equal(last.PNG, before.PNG) {
			t.Fatal("the keys changed nothing on the screen")
		}
		// The target's display shrinks during the session: the server reactivates at the new
		// size, and the recording goes on at it.
		if out, err := exec.Command("docker", "exec", target.container, "sh", "-c", "DISPLAY=:1 xrandr -s 1024x768").CombinedOutput(); err != nil {
			t.Fatalf("xrandr: %v\n%s", err, out)
		}
		read(5 * time.Second)
		if last.Width != 1024 || last.Height != 768 {
			t.Fatalf("after the display shrank, the last frame is %dx%d, not 1024x768", last.Width, last.Height)
		}
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); windows && dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "recording-shown-last.png"), last.PNG, 0o644)
	}
	// The operator leaves: the relay ends and the recording is sealed.
	_ = conn.Close(websocket.StatusNormalClosure, "operator left")

	// The auditor, as the Gateway asks for them: the recorder authorizes the actor's roles.
	gatewayTLS, err := identity(mtls.APIGateway).GRPCClientTLS(mtls.Peer{URL: recorderURL, Service: mtls.VideoRecorder})
	if err != nil {
		t.Fatal(err)
	}
	grpcConn, err := grpc.NewClient("127.0.0.1:"+grpcPort, grpc.WithTransportCredentials(credentials.NewTLS(gatewayTLS)))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = grpcConn.Close() })
	reader := recordingv1.NewVideoRecordingClient(grpcConn)
	replayed := map[uint64]*recordingv1.VideoFrameData{}
	var complete bool
	waitFor(t, 30*time.Second, "the sealed recording", video, func() bool {
		replayed, complete = map[uint64]*recordingv1.VideoFrameData{}, false
		// Segment after segment, until there is none: the last one says whether it is sealed.
		for first := int64(1); ; {
			segment, err := reader.GetVideoSegment(ctx, &recordingv1.GetVideoSegmentRequest{
				SessionId: sessionID, FirstSequence: first, ActorUserId: "auditor-1", ActorRoles: []string{"session-auditor"}})
			if status.Code(err) == codes.NotFound && first > 1 {
				return complete
			}
			if err != nil {
				return false
			}
			for i, frame := range segment.GetFrames() {
				replayed[uint64(segment.GetFirstSequence())+uint64(i)] = frame
			}
			complete = segment.GetComplete()
			first = segment.GetLastSequence() + 1
		}
	})
	if !complete {
		t.Fatal("the recording of an ended session is not sealed")
	}
	for sequence := uint64(1); sequence <= uint64(len(replayed)); sequence++ {
		if replayed[sequence] == nil {
			t.Fatalf("frame %d missing from %d recorded: the recording is not contiguous", sequence, len(replayed))
		}
	}
	sizes := map[string]int{}
	for sequence, frame := range shown {
		got := replayed[sequence]
		if got == nil {
			t.Fatalf("frame %d was shown and not recorded", sequence)
		}
		if !bytes.Equal(got.GetFrameData(), frame.PNG) {
			t.Fatalf("frame %d: %d bytes replayed differ from the %d shown", sequence, len(got.GetFrameData()), len(frame.PNG))
		}
	}
	for _, frame := range replayed {
		config, err := png.DecodeConfig(bytes.NewReader(frame.GetFrameData()))
		if err != nil {
			t.Fatalf("a recorded frame is not a PNG: %v", err)
		}
		sizes[fmt.Sprintf("%dx%d", config.Width, config.Height)]++
	}
	t.Logf("%d frame(s) shown, %d recorded, sealed; sizes recorded: %v", len(shown), len(replayed), sizes)
	if sizes["1280x800"] == 0 || !windows && sizes["1024x768"] == 0 {
		t.Fatalf("the recording does not hold the sizes of the session: %v", sizes)
	}
	if !audit.saw("auditor-1", sessionID) {
		t.Fatal("the read is not on the audit record")
	}

	// Without the right, nothing: not a byte, and the refusal is not an answer to retry.
	_, err = reader.GetVideoSegment(ctx, &recordingv1.GetVideoSegmentRequest{
		SessionId: sessionID, FirstSequence: 1, ActorUserId: "operator-1", ActorRoles: []string{"screen-ops"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("a reader without the right: %v", err)
	}
	// The proxy's identity records; it does not read.
	proxyTLS, err := identity(mtls.RDPVNCProxy).GRPCClientTLS(mtls.Peer{URL: recorderURL, Service: mtls.VideoRecorder})
	if err != nil {
		t.Fatal(err)
	}
	proxyConn, err := grpc.NewClient("127.0.0.1:"+grpcPort, grpc.WithTransportCredentials(credentials.NewTLS(proxyTLS)))
	if err != nil {
		t.Fatal(err)
	}
	defer proxyConn.Close()
	_, err = recordingv1.NewVideoRecordingClient(proxyConn).GetVideoSegment(ctx, &recordingv1.GetVideoSegmentRequest{
		SessionId: sessionID, FirstSequence: 1, ActorUserId: "auditor-1", ActorRoles: []string{"session-auditor"}})
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("the proxy read a recording: %v", err)
	}
}

// -- the RDP target ---------------------------------------------------------------------------

type recordingRDPTarget struct {
	address, pin, container, user, password, name string
	roots                                         *x509.CertPool
	// What the codec asks for: FreeRDP's server answers another size with a reactivation.
	askWidth, askHeight uint16
	keyPace             time.Duration
}

// recordingWindowsTarget is the Windows of test.env (test/integration/testdata/rdp/windows), ready:
// this runs after the screen test, which waits for the installation.
func recordingWindowsTarget(t *testing.T) recordingRDPTarget {
	t.Helper()
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatalf("RDP_WINDOWS_CA_FILE: %v", err)
	}
	target := recordingRDPTarget{address: os.Getenv("RDP_WINDOWS_ADDRESS"), pin: os.Getenv("RDP_WINDOWS_PIN"),
		user: os.Getenv("RDP_WINDOWS_USER"), password: os.Getenv("RDP_WINDOWS_PASSWORD"), name: os.Getenv("RDP_WINDOWS_SERVER_NAME"),
		roots: x509.NewCertPool(), askWidth: 1280, askHeight: 800, keyPace: 50 * time.Millisecond}
	if !target.roots.AppendCertsFromPEM(raw) || target.address == "" || target.pin == "" || target.user == "" || target.password == "" || target.name == "" {
		t.Fatal("RDP_WINDOWS_ADDRESS, _USER, _PASSWORD, _PIN, _SERVER_NAME and _CA_FILE are all needed")
	}
	return target
}

func startRecordingRDPTarget(t *testing.T, root string) recordingRDPTarget {
	t.Helper()
	const image = "openbastion-test-freerdp:latest"
	if out, err := exec.Command("docker", "build", "-q", "-t", image, filepath.Join(root, "test", "integration", "testdata", "rdp", "freerdp")).CombinedOutput(); err != nil {
		t.Fatalf("docker build: %v\n%s", err, out)
	}
	container := fmt.Sprintf("ob-rdp-recording-%d", os.Getpid())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::3389",
		"-e", "RDP_USER="+recordingRDPUser, "-e", "RDP_PASSWORD="+recordingRDPPassword, "-e", "RDP_DISPLAY=resizable", image).CombinedOutput(); err != nil {
		t.Fatalf("docker run: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	port, err := exec.Command("docker", "port", container, "3389/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	target := recordingRDPTarget{address: strings.TrimSpace(strings.Split(string(port), "\n")[0]), container: container,
		user: recordingRDPUser, password: recordingRDPPassword, name: recordingRDPName, askWidth: 1024, askHeight: 768}
	deadline := time.Now().Add(30 * time.Second)
	for {
		raw, err := exec.Command("docker", "exec", container, "sh", "-c", "grep -qs :0D3D /proc/net/tcp /proc/net/tcp6 && cat ~/.config/freerdp/shadow/shadow.crt").Output()
		if block, _ := pem.Decode(raw); err == nil && block != nil {
			sum := sha256.Sum256(block.Bytes)
			target.pin = hex.EncodeToString(sum[:])
			target.roots = x509.NewCertPool()
			target.roots.AppendCertsFromPEM(raw)
			return target
		}
		if time.Now().After(deadline) {
			logs, _ := exec.Command("docker", "logs", container).CombinedOutput()
			t.Fatalf("the target did not start: %s", logs)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

type recordingVault struct{ fetched proxycore.Fetched }

func (v recordingVault) FetchCredential(context.Context, string, string) (proxycore.Fetched, error) {
	f := v.fetched
	f.Material = append([]byte(nil), v.fetched.Material...)
	return f, nil
}

// -- the Video Recorder, its own process --------------------------------------------------------

type recorderProcess struct{ out *lockedBuffer }

func startVideoRecorder(t *testing.T, root, pkiDir, httpPort, grpcPort, dsn, s3URL, authzURL, auditURL string) *recorderProcess {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "video-recorder")
	build := exec.Command("go", "build", "-o", bin, "./services/recording-audit/video-recorder/cmd/video-recorder")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building the Video Recorder: %v\n%s", err, out)
	}
	cmd := exec.Command(bin)
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"), "HOME=" + os.Getenv("HOME"),
		"PORT=" + httpPort, "GRPC_PORT=" + grpcPort, "DATABASE_URL=" + dsn,
		"INTERNAL_TLS=required", "TLS_TRUST_DOMAIN=" + recordingTrustDomain,
		"TLS_CERT_FILE=" + pki.CertFile(pkiDir, mtls.VideoRecorder), "TLS_KEY_FILE=" + pki.KeyFile(pkiDir, mtls.VideoRecorder),
		"TLS_CA_FILE=" + pki.CAFile(pkiDir),
		"VIDEO_RECORDER_KMS_KEY_HEX=" + strings.Repeat("ab", 32),
		"S3_ENDPOINT=" + s3URL, "S3_BUCKET=screens", "S3_ACCESS_KEY=test", "S3_SECRET_KEY=test-secret", "S3_ALLOW_HTTP=true", "S3_CREATE_BUCKET=true",
		"AUTHORIZATION_URL=" + authzURL, "AUDIT_URL=" + auditURL,
	}
	p := &recorderProcess{out: &lockedBuffer{}}
	cmd.Stdout, cmd.Stderr = p.out, p.out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("video-recorder:\n%s", p.out.String())
		}
	})
	return p
}

// serveAs serves one route under service's identity, to callers the recorder is: mutual TLS, as
// the real service would.
func serveAs(t *testing.T, rt *mtls.Runtime, method, path string, handler http.HandlerFunc) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, handler)
	server := rt.Server(listener.Addr().String(), mux, []mtls.Rule{{Method: method, Path: path, Callers: []string{mtls.VideoRecorder}}})
	go func() { _ = server.ServeTLS(listener, "", "") }()
	t.Cleanup(func() { _ = server.Close() })
	return "https://" + listener.Addr().String()
}

type recordingAuditSpy struct {
	mu     sync.Mutex
	events []string
}

func (a *recordingAuditSpy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	var event struct {
		ActorID    string `json:"actor_id"`
		Action     string `json:"action"`
		ResourceID string `json:"resource_id"`
	}
	_ = json.NewDecoder(r.Body).Decode(&event)
	a.mu.Lock()
	a.events = append(a.events, event.ActorID+" "+event.Action+" "+event.ResourceID)
	a.mu.Unlock()
	_ = json.NewEncoder(w).Encode(map[string]string{"event_id": "evt-" + strconv.Itoa(len(a.events))})
}

func (a *recordingAuditSpy) saw(actor, sessionID string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, event := range a.events {
		if strings.HasPrefix(event, actor+" ") && strings.HasSuffix(event, " "+sessionID) {
			return true
		}
	}
	return false
}

// -- an S3 endpoint of the size the Video Recorder needs (as test/integration's) -----------------

type recordingObjectStore struct {
	URL     string
	mu      sync.Mutex
	objects map[string][]byte
}

func newRecordingObjectStore(t *testing.T) *recordingObjectStore {
	t.Helper()
	store := &recordingObjectStore{objects: map[string][]byte{}}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimPrefix(r.URL.Path, "/")
		isBucket := !strings.Contains(strings.TrimSuffix(key, "/"), "/")
		switch {
		case r.URL.Query().Has("location"):
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<LocationConstraint xmlns="http://s3.amazonaws.com/doc/2006-03-01/"></LocationConstraint>`)
		case isBucket:
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodPut:
			body, _ := io.ReadAll(r.Body)
			if strings.HasPrefix(r.Header.Get("X-Amz-Content-Sha256"), "STREAMING-") {
				body = decodeChunked(t, body)
			}
			store.mu.Lock()
			store.objects[key] = body
			store.mu.Unlock()
			w.Header().Set("ETag", `"`+hex.EncodeToString(sha256.New().Sum(body)[:16])+`"`)
		case r.Method == http.MethodGet || r.Method == http.MethodHead:
			store.mu.Lock()
			body, ok := store.objects[key]
			store.mu.Unlock()
			if !ok {
				w.WriteHeader(http.StatusNotFound)
				return
			}
			w.Header().Set("ETag", `"fake"`)
			w.Header().Set("Last-Modified", time.Now().UTC().Format(http.TimeFormat))
			w.Header().Set("Accept-Ranges", "bytes")
			http.ServeContent(w, r, "", time.Now(), bytes.NewReader(body))
		default:
			w.WriteHeader(http.StatusMethodNotAllowed)
		}
	}))
	t.Cleanup(srv.Close)
	store.URL = srv.URL
	return store
}

// decodeChunked undoes the aws-chunked framing a signed S3 client puts around a body over HTTP.
func decodeChunked(t *testing.T, framed []byte) []byte {
	var out []byte
	for {
		line, rest, ok := bytes.Cut(framed, []byte("\r\n"))
		if !ok {
			t.Errorf("aws-chunked: no chunk header in %d bytes", len(framed))
			return out
		}
		sizeField, _, _ := bytes.Cut(line, []byte(";"))
		size, err := strconv.ParseUint(string(sizeField), 16, 32)
		if err != nil || uint64(len(rest)) < size {
			t.Errorf("aws-chunked: chunk header %q over %d bytes", line, len(rest))
			return out
		}
		if size == 0 {
			return out
		}
		out = append(out, rest[:size]...)
		framed = bytes.TrimPrefix(rest[size:], []byte("\r\n"))
	}
}

// -- small things --------------------------------------------------------------------------------

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
}

func waitFor(t *testing.T, limit time.Duration, what string, p *recorderProcess, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %s for %s\n%s", limit, what, p.out.String())
		}
		time.Sleep(250 * time.Millisecond)
	}
}

func contains(values []string, want string) bool {
	for _, v := range values {
		if v == want {
			return true
		}
	}
	return false
}

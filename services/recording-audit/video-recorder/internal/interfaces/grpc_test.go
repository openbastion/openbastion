package interfaces

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/mtls/pki"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/infrastructure"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type grpcObjects struct {
	values map[string][]byte
	err    error
}

func (s *grpcObjects) Put(_ context.Context, key string, value []byte) error {
	if s.err != nil {
		return s.err
	}
	s.values[key] = append([]byte(nil), value...)
	return nil
}

func (s *grpcObjects) Get(_ context.Context, key string) ([]byte, error) {
	if s.err != nil {
		return nil, s.err
	}
	value, ok := s.values[key]
	if !ok {
		return nil, errors.New("object missing")
	}
	return append([]byte(nil), value...), nil
}

func (*grpcObjects) Ready(context.Context) error { return nil }

type grpcAuthz struct{}

func (grpcAuthz) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return true, "", nil
}

type grpcAudit struct{}

func (grpcAudit) EmitEvent(context.Context, string, string, string, string, bool, map[string]string) error {
	return nil
}

func newGRPCTestService(t *testing.T, objects *grpcObjects) (*application.RecorderService, *infrastructure.MemoryStore) {
	t.Helper()
	store := infrastructure.NewMemoryStore()
	key, err := infrastructure.NewLocalKEKFromHexKey("abababababababababababababababababababababababababababababababab")
	if err != nil {
		t.Fatal(err)
	}
	return application.NewRecorderService(store, objects, key, grpcAuthz{}, grpcAudit{}), store
}

func testFrame() *recordingv1.VideoFrameData {
	var encoded bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 1, G: 2, B: 3, A: 255})
	if err := png.Encode(&encoded, img); err != nil {
		panic(err)
	}
	return &recordingv1.VideoFrameData{
		Ts:        timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		FrameData: encoded.Bytes(), Codec: "png",
	}
}

func TestStreamVideoSegmentsAcknowledgesOnlyPersistedSegmentsAndTerminalMarker(t *testing.T) {
	objects := &grpcObjects{values: make(map[string][]byte)}
	svc, store := newGRPCTestService(t, objects)
	server := NewGRPCServer(svc, nil)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///video-recorder",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client := recordingv1.NewVideoRecordingClient(conn)
	stream, err := client.StreamVideoSegments(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if err := stream.Send(&recordingv1.VideoSegment{
		SessionId: "session-1", FirstSequence: 1, LastSequence: 1,
		Frames: []*recordingv1.VideoFrameData{testFrame()},
	}); err != nil {
		t.Fatal(err)
	}
	ack, err := stream.Recv()
	if err != nil || ack.GetThroughSequence() != 1 || ack.GetComplete() {
		t.Fatalf("segment ack: %+v, %v", ack, err)
	}
	if len(objects.values) != 1 {
		t.Fatalf("segment was acknowledged without one persisted encrypted object: %d", len(objects.values))
	}

	if err := stream.Send(&recordingv1.VideoSegment{
		SessionId: "session-1", Terminal: true, TerminalThroughSequence: 1,
	}); err != nil {
		t.Fatal(err)
	}
	ack, err = stream.Recv()
	if err != nil || ack.GetThroughSequence() != 1 || !ack.GetComplete() {
		t.Fatalf("terminal ack: %+v, %v", ack, err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); !errors.Is(err, io.EOF) {
		t.Fatalf("completed stream returned %v, want EOF", err)
	}

	stored, err := store.GetSegment(context.Background(), "session-1", 1)
	if err != nil || !stored.Complete {
		t.Fatalf("recording not durably complete: %+v err=%v", stored, err)
	}
}

func TestStreamEndWithoutTerminalMarkerLeavesRecordingIncomplete(t *testing.T) {
	objects := &grpcObjects{values: make(map[string][]byte)}
	svc, store := newGRPCTestService(t, objects)
	server := NewGRPCServer(svc, nil)
	listener := bufconn.Listen(1 << 20)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(server.Stop)

	conn, err := grpc.NewClient("passthrough:///video-recorder",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	stream, err := recordingv1.NewVideoRecordingClient(conn).StreamVideoSegments(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.Send(&recordingv1.VideoSegment{
		SessionId: "session-incomplete", FirstSequence: 1, LastSequence: 1,
		Frames: []*recordingv1.VideoFrameData{testFrame()},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	if _, err := stream.Recv(); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("stream without terminal marker returned %v, want FailedPrecondition", err)
	}
	stored, err := store.GetSegment(context.Background(), "session-incomplete", 1)
	if err != nil || stored.Complete {
		t.Fatalf("unmarked stream should stay incomplete: %+v err=%v", stored, err)
	}
}

func TestGRPCCallerRulesAuthorizeOnlyExpectedServiceIdentities(t *testing.T) {
	runtime, certs := testRuntimeAndCertificates(t)
	tests := []struct {
		name, identity, method string
		wantCode               codes.Code
		wantCaller             string
	}{
		{"RDP/VNC proxy ingests", mtls.RDPVNCProxy, "/openbastion.recording.v1.VideoRecording/StreamVideoSegments", codes.OK, mtls.RDPVNCProxy},
		{"Gateway cannot ingest", mtls.APIGateway, "/openbastion.recording.v1.VideoRecording/StreamVideoSegments", codes.PermissionDenied, ""},
		{"Gateway can read", mtls.APIGateway, "/openbastion.recording.v1.VideoRecording/GetVideoSegment", codes.OK, mtls.APIGateway},
		{"RDP/VNC proxy cannot read", mtls.RDPVNCProxy, "/openbastion.recording.v1.VideoRecording/GetVideoSegment", codes.PermissionDenied, ""},
		{"Agent cannot ingest", "agent", "/openbastion.recording.v1.VideoRecording/StreamVideoSegments", codes.PermissionDenied, ""},
		{"Agent cannot read", "agent", "/openbastion.recording.v1.VideoRecording/GetVideoSegment", codes.PermissionDenied, ""},
		{"Agent cannot probe recorder", "agent", "/openbastion.recording.v1.VideoRecording/CheckReadiness", codes.PermissionDenied, ""},
		{"unknown method denied", mtls.RDPVNCProxy, "/openbastion.recording.v1.VideoRecording/Unknown", codes.PermissionDenied, ""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			leaf := certs[test.identity]
			ctx := grpcpeer.NewContext(context.Background(), &grpcpeer.Peer{AuthInfo: credentials.TLSInfo{
				State: tls.ConnectionState{
					PeerCertificates: []*x509.Certificate{leaf.Cert},
					VerifiedChains:   [][]*x509.Certificate{{leaf.Cert}},
				},
			}})
			caller, err := authenticatedCaller(ctx, test.method, GRPCCallerRules(), runtime)
			if status.Code(err) != test.wantCode || caller != test.wantCaller {
				t.Fatalf("authenticatedCaller = %q, %v; want %q and %s", caller, err, test.wantCaller, test.wantCode)
			}
		})
	}
}

func testRuntimeAndCertificates(t *testing.T) (*mtls.Runtime, map[string]*pki.Leaf) {
	t.Helper()
	const trustDomain = "openbastion.local"
	ca, err := pki.NewCA(trustDomain, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	serviceLeaf, err := ca.Issue(mtls.VideoRecorder, pki.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	serviceDir := filepath.Join(dir, mtls.VideoRecorder)
	if err := os.MkdirAll(serviceDir, 0o700); err != nil {
		t.Fatal(err)
	}
	certPath, keyPath, caPath := filepath.Join(serviceDir, "cert.pem"), filepath.Join(serviceDir, "key.pem"), filepath.Join(dir, "ca.pem")
	for path, content := range map[string][]byte{
		certPath: serviceLeaf.CertPEM, keyPath: serviceLeaf.KeyPEM, caPath: ca.CertPEM(),
	} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	runtime, err := mtls.SetupWith(mtls.VideoRecorder, mtls.Settings{
		Mode: mtls.Required, CertFile: certPath, KeyFile: keyPath, CAFile: caPath, TrustDomain: trustDomain,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaves := make(map[string]*pki.Leaf)
	for _, identity := range []string{mtls.RDPVNCProxy, mtls.APIGateway, "agent"} {
		leaf, err := ca.Issue(identity, pki.IssueOptions{})
		if err != nil {
			t.Fatal(err)
		}
		leaves[identity] = leaf
	}
	return runtime, leaves
}

func TestGRPCCallerRejectsCertificateFromWrongTrustDomain(t *testing.T) {
	runtime, _ := testRuntimeAndCertificates(t)
	otherCA, err := pki.NewCA("other.example", time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := otherCA.Issue(mtls.RDPVNCProxy, pki.IssueOptions{})
	if err != nil {
		t.Fatal(err)
	}
	ctx := grpcpeer.NewContext(context.Background(), &grpcpeer.Peer{AuthInfo: credentials.TLSInfo{
		State: tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf.Cert},
			VerifiedChains:   [][]*x509.Certificate{{leaf.Cert}},
		},
	}})
	_, err = authenticatedCaller(ctx, "/openbastion.recording.v1.VideoRecording/StreamVideoSegments", GRPCCallerRules(), runtime)
	if status.Code(err) != codes.Unauthenticated {
		t.Fatalf("wrong trust domain returned %v, want Unauthenticated", err)
	}
}

func TestHTTPHealthRoutesRequireGET(t *testing.T) {
	server := NewHTTPServer(nil)
	for _, method := range []string{"GET", "POST"} {
		request := httptest.NewRequest(method, "/healthz", nil)
		response := httptest.NewRecorder()
		server.Routes().ServeHTTP(response, request)
		want := 200
		if method != "GET" {
			want = 405
		}
		if response.Code != want {
			t.Errorf("%s /healthz = %d, want %d", method, response.Code, want)
		}
	}
}

func TestGRPCCallerRulesIncludeRDPAndGatewayOnlyMethods(t *testing.T) {
	rules := GRPCCallerRules()
	if len(rules) != 3 {
		t.Fatalf("got %d RPC rules, want 3", len(rules))
	}
	for _, rule := range rules {
		if len(rule.Callers) == 0 {
			t.Fatalf("RPC %s has no callers", rule.Method)
		}
		for _, caller := range rule.Callers {
			if !mtls.ValidServiceName(caller) {
				t.Fatalf("RPC %s has invalid caller %q", rule.Method, caller)
			}
		}
	}
}

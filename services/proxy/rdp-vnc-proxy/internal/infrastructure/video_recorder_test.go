package infrastructure

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/screenstream"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
)

type videoRecorderTestServer struct {
	recordingv1.UnimplementedVideoRecordingServer
	mu        sync.Mutex
	ready     bool
	ackOffset int64
	frames    []uint64
	codecs    []string
	data      [][]byte
	complete  bool
}

func (s *videoRecorderTestServer) CheckReadiness(context.Context, *recordingv1.CheckVideoRecorderReadinessRequest) (*recordingv1.CheckVideoRecorderReadinessResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return &recordingv1.CheckVideoRecorderReadinessResponse{Ready: s.ready}, nil
}

func (s *videoRecorderTestServer) StreamVideoSegments(stream grpc.BidiStreamingServer[recordingv1.VideoSegment, recordingv1.VideoSegmentAck]) error {
	var sessionID string
	var through int64
	terminal := false
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if !terminal {
				return status.Error(codes.FailedPrecondition, "terminal marker required")
			}
			return nil
		}
		if err != nil {
			return err
		}
		if sessionID == "" {
			sessionID = message.GetSessionId()
		} else if message.GetSessionId() != sessionID {
			return status.Error(codes.InvalidArgument, "session changed")
		}
		if message.GetTerminal() {
			if message.GetTerminalThroughSequence() != through {
				return status.Error(codes.FailedPrecondition, "terminal sequence mismatch")
			}
			terminal = true
			s.mu.Lock()
			s.complete = true
			s.mu.Unlock()
			if err := stream.Send(&recordingv1.VideoSegmentAck{SessionId: sessionID, ThroughSequence: through, Complete: true}); err != nil {
				return err
			}
			continue
		}
		if terminal || message.GetFirstSequence() != through+1 || message.GetLastSequence() != message.GetFirstSequence() || len(message.GetFrames()) != 1 {
			return status.Error(codes.InvalidArgument, "invalid frame segment")
		}
		through = message.GetLastSequence()
		s.mu.Lock()
		s.frames = append(s.frames, uint64(through))
		s.codecs = append(s.codecs, message.GetFrames()[0].GetCodec())
		s.data = append(s.data, message.GetFrames()[0].GetFrameData())
		ackOffset := s.ackOffset
		s.mu.Unlock()
		if err := stream.Send(&recordingv1.VideoSegmentAck{SessionId: sessionID, ThroughSequence: through + ackOffset}); err != nil {
			return err
		}
	}
}

func newVideoRecorderTestClient(t *testing.T, server *videoRecorderTestServer) *VideoRecorderClient {
	t.Helper()
	listener := bufconn.Listen(1 << 20)
	grpcServer := grpc.NewServer()
	recordingv1.RegisterVideoRecordingServer(grpcServer, server)
	go func() { _ = grpcServer.Serve(listener) }()
	t.Cleanup(grpcServer.Stop)

	conn, err := grpc.NewClient("passthrough:///video-recorder",
		grpc.WithContextDialer(func(context.Context, string) (net.Conn, error) { return listener.Dial() }),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithDefaultCallOptions(grpc.MaxCallSendMsgSize(maxVideoRecorderMessageBytes), grpc.MaxCallRecvMsgSize(maxVideoRecorderMessageBytes)),
	)
	if err != nil {
		t.Fatal(err)
	}
	client := &VideoRecorderClient{
		client:  recordingv1.NewVideoRecordingClient(conn),
		conn:    conn,
		streams: make(map[string]*videoRecordingStream),
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

func testScreenFrame(t *testing.T, sequence uint64) screenstream.Message {
	t.Helper()
	var encoded bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 20, G: 30, B: 40, A: 255})
	if err := png.Encode(&encoded, img); err != nil {
		t.Fatal(err)
	}
	return screenstream.Message{
		Type: screenstream.TypeFrame, Sequence: sequence, Timestamp: time.Date(2026, 11, 3, 14, 0, int(sequence), 0, time.UTC),
		Width: 1, Height: 1, PNG: encoded.Bytes(),
	}
}

func TestNewVideoRecorderClientRequiresAnExplicitTLSModeAndOrigin(t *testing.T) {
	if _, err := NewVideoRecorderClient(nil, "http://127.0.0.1:8081"); err == nil {
		t.Fatal("nil mTLS runtime accepted")
	}
	runtime, err := mtls.SetupWith(mtls.RDPVNCProxy, mtls.Settings{Mode: mtls.Disabled})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVideoRecorderClient(runtime, "https://127.0.0.1:8081"); err == nil {
		t.Fatal("HTTPS endpoint accepted with INTERNAL_TLS=disabled")
	}
	for _, endpoint := range []string{
		"http://user@127.0.0.1:8081",
		"http://127.0.0.1:8081/path",
		"http://127.0.0.1:8081?token=secret",
	} {
		if _, err := NewVideoRecorderClient(runtime, endpoint); err == nil {
			t.Fatalf("non-origin Video Recorder endpoint accepted: %q", endpoint)
		}
	}
	client, err := NewVideoRecorderClient(runtime, "http://127.0.0.1:8081")
	if err != nil {
		t.Fatalf("valid development endpoint rejected: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func TestVideoRecorderClientAcknowledgesPersistedFramesAndSeals(t *testing.T) {
	server := &videoRecorderTestServer{ready: true}
	client := newVideoRecorderTestClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	if err := client.Ready(ctx); err != nil {
		t.Fatalf("Ready: %v", err)
	}
	ack, err := client.Record(ctx, "session-vnc-1", testScreenFrame(t, 1))
	if err != nil || ack != 1 {
		t.Fatalf("Record = %d, %v; want sequence 1 acknowledged", ack, err)
	}
	if err := client.Seal(ctx, "session-vnc-1", ack); err != nil {
		t.Fatalf("Seal: %v", err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.frames) != 1 || server.frames[0] != 1 || !server.complete {
		t.Fatalf("recorder did not receive the frame and terminal marker: frames=%v complete=%v", server.frames, server.complete)
	}
}

func TestVideoRecorderClientRefusesUnreadyRecorder(t *testing.T) {
	client := newVideoRecorderTestClient(t, &videoRecorderTestServer{ready: false})
	if err := client.Ready(context.Background()); !errors.Is(err, ErrVideoRecorderUnavailable) {
		t.Fatalf("Ready with unready recorder = %v, want ErrVideoRecorderUnavailable", err)
	}
}

func TestVideoRecorderClientRejectsAmbiguousAcknowledgementAndDoesNotSeal(t *testing.T) {
	server := &videoRecorderTestServer{ready: true, ackOffset: 1}
	client := newVideoRecorderTestClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if _, err := client.Record(ctx, "session-vnc-ambiguous", testScreenFrame(t, 1)); !errors.Is(err, ErrVideoRecorderProtocol) {
		t.Fatalf("Record with wrong sequence acknowledgement = %v, want ErrVideoRecorderProtocol", err)
	}
	if err := client.Seal(ctx, "session-vnc-ambiguous", 0); err == nil {
		t.Fatal("Seal claimed success after an ambiguous frame acknowledgement")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.complete {
		t.Fatal("recording marked complete after the acknowledged sequence was ambiguous")
	}
}

func TestVideoRecorderClientRejectsInvalidSessionID(t *testing.T) {
	client := newVideoRecorderTestClient(t, &videoRecorderTestServer{ready: true})
	for _, sessionID := range []string{"", "session\nforged", string(bytes.Repeat([]byte{'x'}, maxVideoSessionIDBytes+1))} {
		if _, err := client.Record(context.Background(), sessionID, testScreenFrame(t, 1)); !errors.Is(err, ErrVideoRecorderProtocol) {
			t.Fatalf("Record with invalid session id %q = %v, want ErrVideoRecorderProtocol", sessionID, err)
		}
	}
}

func TestVideoRecorderClientRejectsSequenceGap(t *testing.T) {
	client := newVideoRecorderTestClient(t, &videoRecorderTestServer{ready: true})
	if _, err := client.Record(context.Background(), "session-vnc-gap", testScreenFrame(t, 2)); !errors.Is(err, ErrVideoRecorderProtocol) {
		t.Fatalf("Record sequence gap = %v, want ErrVideoRecorderProtocol", err)
	}
}

// A partial frame goes to the Recorder as the operator receives it: its FRAME_DELTA message, under
// codec png-delta-v1; a key frame stays its PNG (ADR-0092 §5).
func TestVideoRecorderClientSendsPartialFramesAsTheyAreShown(t *testing.T) {
	server := &videoRecorderTestServer{ready: true}
	client := newVideoRecorderTestClient(t, server)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	key := testScreenFrame(t, 1)
	if _, err := client.Record(ctx, "session-vnc-1", key); err != nil {
		t.Fatal(err)
	}
	delta := screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: 2, Timestamp: key.Timestamp.Add(time.Millisecond),
		Width: key.Width, Height: key.Height, Rects: []screenstream.Rect{{Width: 1, Height: 1, PNG: key.PNG}}}
	if ack, err := client.Record(ctx, "session-vnc-1", delta); err != nil || ack != 2 {
		t.Fatalf("Record of a partial frame = %d, %v", ack, err)
	}
	wire, err := screenstream.Encode(delta)
	if err != nil {
		t.Fatal(err)
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if len(server.codecs) != 2 || server.codecs[0] != "png" || server.codecs[1] != "png-delta-v1" {
		t.Fatalf("codecs %v", server.codecs)
	}
	if !bytes.Equal(server.data[0], key.PNG) || !bytes.Equal(server.data[1], wire) {
		t.Fatal("the Recorder did not get the key frame's PNG and the partial frame's message")
	}
}

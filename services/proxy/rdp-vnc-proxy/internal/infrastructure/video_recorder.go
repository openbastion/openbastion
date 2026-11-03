package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/url"
	"sync"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/timestamppb"
)

var (
	ErrVideoRecorderUnavailable = errors.New("rdp-vnc-proxy: video recorder is unavailable")
	ErrVideoRecorderProtocol    = errors.New("rdp-vnc-proxy: video recorder acknowledgement is invalid")
)

const (
	maxVideoRecorderMessageBytes = 5 << 20
	maxVideoSessionIDBytes       = 256
)

// VideoRecorderClient implements the shared screen lifecycle's durable recorder
// and readiness contracts. One acknowledged gRPC stream is kept per session so
// Seal can send its terminal marker on the same recording after relay cancellation.
type VideoRecorderClient struct {
	client recordingv1.VideoRecordingClient
	conn   *grpc.ClientConn

	mu      sync.Mutex
	streams map[string]*videoRecordingStream
	closed  bool
}

type videoRecordingStream struct {
	ctx    context.Context
	cancel context.CancelFunc
	stream grpc.BidiStreamingClient[recordingv1.VideoSegment, recordingv1.VideoSegmentAck]
	acks   chan videoRecorderAck

	mu       sync.Mutex
	lastSent int64
	sealed   bool
}

type videoRecorderAck struct {
	ack *recordingv1.VideoSegmentAck
	err error
}

var _ proxycore.FrameRecorder = (*VideoRecorderClient)(nil)
var _ proxycore.ScreenRecorderGate = (*VideoRecorderClient)(nil)

// NewVideoRecorderClient creates a service-identity-pinned gRPC client. Plaintext
// is permitted only when the runtime is explicitly configured with INTERNAL_TLS=disabled.
func NewVideoRecorderClient(runtime *mtls.Runtime, endpoint string) (*VideoRecorderClient, error) {
	if runtime == nil {
		return nil, errors.New("rdp-vnc-proxy: Video Recorder requires an mTLS runtime")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("rdp-vnc-proxy: VIDEO_RECORDER_GRPC_URL must be an origin with a host")
	}
	wantScheme := "https"
	var transport credentials.TransportCredentials
	if runtime.Enabled() {
		tlsConfig, err := runtime.GRPCClientTLS(mtls.Peer{URL: endpoint, Service: mtls.VideoRecorder})
		if err != nil {
			return nil, err
		}
		transport = credentials.NewTLS(tlsConfig)
	} else {
		wantScheme = "http"
		transport = insecure.NewCredentials()
	}
	if u.Scheme != wantScheme {
		return nil, fmt.Errorf("rdp-vnc-proxy: VIDEO_RECORDER_GRPC_URL must use %s for the configured INTERNAL_TLS mode", wantScheme)
	}
	conn, err := grpc.NewClient(u.Host,
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(
			grpc.MaxCallRecvMsgSize(maxVideoRecorderMessageBytes),
			grpc.MaxCallSendMsgSize(maxVideoRecorderMessageBytes),
		),
	)
	if err != nil {
		return nil, fmt.Errorf("rdp-vnc-proxy: creating Video Recorder gRPC connection: %w", err)
	}
	return &VideoRecorderClient{
		client:  recordingv1.NewVideoRecordingClient(conn),
		conn:    conn,
		streams: make(map[string]*videoRecordingStream),
	}, nil
}

// Ready proves the Video Recorder can accept a session before the proxy spends
// the Vault's one-use credential scope.
func (c *VideoRecorderClient) Ready(ctx context.Context) error {
	if c == nil || c.client == nil || ctx == nil {
		return ErrVideoRecorderUnavailable
	}
	response, err := c.client.CheckReadiness(ctx, &recordingv1.CheckVideoRecorderReadinessRequest{})
	if err != nil || response == nil || !response.GetReady() {
		return fmt.Errorf("%w: readiness check failed", ErrVideoRecorderUnavailable)
	}
	return nil
}

// Record sends one frame and returns only after the Video Recorder acknowledges
// the persisted sequence. An ambiguous or mismatched acknowledgement fails closed.
func (c *VideoRecorderClient) Record(ctx context.Context, sessionID string, frame screenstream.Message) (uint64, error) {
	if ctx == nil || !usableVideoSessionID(sessionID) || frame.Type != screenstream.TypeFrame || frame.Sequence == 0 || frame.Sequence > math.MaxInt64 {
		return 0, ErrVideoRecorderProtocol
	}
	if _, err := screenstream.Encode(frame); err != nil {
		return 0, fmt.Errorf("%w: invalid frame", ErrVideoRecorderProtocol)
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	stream, err := c.getOrCreateStream(ctx, sessionID)
	if err != nil {
		return 0, err
	}
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.sealed || int64(frame.Sequence) != stream.lastSent+1 {
		return 0, ErrVideoRecorderProtocol
	}
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	message := &recordingv1.VideoSegment{
		SessionId: sessionID, FirstSequence: int64(frame.Sequence), LastSequence: int64(frame.Sequence),
		Frames: []*recordingv1.VideoFrameData{{
			Ts: timestamppb.New(frame.Timestamp.UTC()), FrameData: append([]byte(nil), frame.PNG...), Codec: "png",
		}},
	}
	if err := message.GetFrames()[0].GetTs().CheckValid(); err != nil {
		return 0, ErrVideoRecorderProtocol
	}
	if err := stream.stream.Send(message); err != nil {
		return 0, fmt.Errorf("%w: sending frame segment", ErrVideoRecorderUnavailable)
	}
	ack, err := waitVideoRecorderAck(ctx, stream.ctx, stream.acks)
	if err != nil {
		if ctx.Err() != nil {
			return 0, ctx.Err()
		}
		return 0, fmt.Errorf("%w: waiting for frame acknowledgement", ErrVideoRecorderUnavailable)
	}
	if ack.ack == nil || ack.ack.GetSessionId() != sessionID || ack.ack.GetComplete() || ack.ack.GetThroughSequence() != int64(frame.Sequence) {
		return 0, ErrVideoRecorderProtocol
	}
	stream.lastSent = int64(frame.Sequence)
	return frame.Sequence, nil
}

// Seal attempts the terminal marker even when the relay context was cancelled.
// The stream is intentionally detached from the first frame's context; this method
// is the sole normal path that terminates it and confirms durable completion.
func (c *VideoRecorderClient) Seal(ctx context.Context, sessionID string, throughSequence uint64) error {
	if ctx == nil || !usableVideoSessionID(sessionID) || throughSequence > math.MaxInt64 {
		return ErrVideoRecorderProtocol
	}
	stream, err := c.getOrCreateStream(ctx, sessionID)
	if err != nil {
		return err
	}
	defer c.removeStream(sessionID, stream)
	stream.mu.Lock()
	defer stream.mu.Unlock()
	if stream.sealed || int64(throughSequence) != stream.lastSent {
		return ErrVideoRecorderProtocol
	}
	stream.sealed = true
	if err := ctx.Err(); err != nil {
		stream.cancel()
		return err
	}
	if err := stream.stream.Send(&recordingv1.VideoSegment{
		SessionId: sessionID, Terminal: true, TerminalThroughSequence: int64(throughSequence),
	}); err != nil {
		stream.cancel()
		return fmt.Errorf("%w: sending terminal marker", ErrVideoRecorderUnavailable)
	}

	var ambiguous bool
	for {
		result, err := waitVideoRecorderAck(ctx, stream.ctx, stream.acks)
		if err != nil {
			stream.cancel()
			return fmt.Errorf("%w: waiting for terminal acknowledgement", ErrVideoRecorderUnavailable)
		}
		if result.ack == nil || result.ack.GetSessionId() != sessionID {
			stream.cancel()
			return ErrVideoRecorderProtocol
		}
		if result.ack.GetComplete() {
			if result.ack.GetThroughSequence() != int64(throughSequence) || ambiguous {
				stream.cancel()
				return ErrVideoRecorderProtocol
			}
			break
		}
		// Any unexpected frame acknowledgement means the persisted sequence
		// was ambiguous to the relay. Drain it, but never claim the recording complete.
		ambiguous = true
	}
	if err := stream.stream.CloseSend(); err != nil {
		stream.cancel()
		return fmt.Errorf("%w: closing video stream", ErrVideoRecorderUnavailable)
	}
	select {
	case <-ctx.Done():
		stream.cancel()
		return ctx.Err()
	case <-stream.ctx.Done():
		return fmt.Errorf("%w: video stream ended before its terminal acknowledgement was drained", ErrVideoRecorderUnavailable)
	case result, ok := <-stream.acks:
		if !ok || !errors.Is(result.err, io.EOF) {
			stream.cancel()
			return fmt.Errorf("%w: video stream did not close cleanly", ErrVideoRecorderUnavailable)
		}
	}
	stream.cancel()
	return nil
}

func (c *VideoRecorderClient) getOrCreateStream(ctx context.Context, sessionID string) (*videoRecordingStream, error) {
	if c == nil || c.client == nil || ctx == nil || !usableVideoSessionID(sessionID) {
		return nil, ErrVideoRecorderUnavailable
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.closed {
		return nil, ErrVideoRecorderUnavailable
	}
	if stream := c.streams[sessionID]; stream != nil {
		return stream, nil
	}
	streamCtx, cancel := context.WithCancel(context.WithoutCancel(ctx))
	grpcStream, err := c.client.StreamVideoSegments(streamCtx)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("%w: opening video stream", ErrVideoRecorderUnavailable)
	}
	stream := &videoRecordingStream{
		ctx: streamCtx, cancel: cancel, stream: grpcStream, acks: make(chan videoRecorderAck, 4),
	}
	c.streams[sessionID] = stream
	go stream.receiveAcks()
	return stream, nil
}

func (s *videoRecordingStream) receiveAcks() {
	for {
		ack, err := s.stream.Recv()
		select {
		case s.acks <- videoRecorderAck{ack: ack, err: err}:
		case <-s.ctx.Done():
			return
		}
		if err != nil {
			return
		}
	}
}

func usableVideoSessionID(id string) bool {
	if id == "" || len(id) > maxVideoSessionIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, r := range id {
		if unicode.IsControl(r) {
			return false
		}
	}
	return true
}

func waitVideoRecorderAck(ctx, streamCtx context.Context, acknowledgements <-chan videoRecorderAck) (videoRecorderAck, error) {
	select {
	case <-ctx.Done():
		return videoRecorderAck{}, ctx.Err()
	case <-streamCtx.Done():
		return videoRecorderAck{}, streamCtx.Err()
	case result, ok := <-acknowledgements:
		if !ok {
			return videoRecorderAck{}, io.EOF
		}
		if errors.Is(result.err, io.EOF) {
			return result, io.EOF
		}
		if result.err != nil {
			return result, result.err
		}
		return result, nil
	}
}

func (c *VideoRecorderClient) removeStream(sessionID string, stream *videoRecordingStream) {
	c.mu.Lock()
	if c.streams[sessionID] == stream {
		delete(c.streams, sessionID)
	}
	c.mu.Unlock()
}

// Close terminates outstanding streams and releases the gRPC connection.
func (c *VideoRecorderClient) Close() error {
	if c == nil {
		return nil
	}
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closed = true
	streams := make([]*videoRecordingStream, 0, len(c.streams))
	for _, stream := range c.streams {
		streams = append(streams, stream)
	}
	c.streams = make(map[string]*videoRecordingStream)
	c.mu.Unlock()
	for _, stream := range streams {
		stream.cancel()
	}
	var closeErr error
	if c.conn != nil {
		closeErr = c.conn.Close()
	}
	for _, stream := range streams {
		stream.mu.Lock()
		stream.sealed = true
		_ = stream.stream.CloseSend()
		stream.mu.Unlock()
	}
	return closeErr
}

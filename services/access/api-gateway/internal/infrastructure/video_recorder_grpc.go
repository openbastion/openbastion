package infrastructure

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	"github.com/openbastion/openbastion/pkg/mtls"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// VideoRecorderGRPCClient reads replay data only from the mTLS-pinned Video Recorder.
type VideoRecorderGRPCClient struct {
	client recordingv1.VideoRecordingClient
	conn   *grpc.ClientConn
}

// NewVideoRecorderGRPCClient binds the Gateway to the Video Recorder identity and transport mode.
func NewVideoRecorderGRPCClient(runtime *mtls.Runtime, endpoint string) (*VideoRecorderGRPCClient, error) {
	if runtime == nil {
		return nil, errors.New("video recorder gRPC client requires an mTLS runtime")
	}
	u, err := url.Parse(endpoint)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("VIDEO_RECORDER_GRPC_URL must be an origin with a host")
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
		return nil, fmt.Errorf("VIDEO_RECORDER_GRPC_URL must use %s for the configured INTERNAL_TLS mode", wantScheme)
	}
	conn, err := grpc.NewClient(
		u.Host,
		grpc.WithTransportCredentials(transport),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(5<<20)),
	)
	if err != nil {
		return nil, fmt.Errorf("creating Video Recorder gRPC connection: %w", err)
	}
	return &VideoRecorderGRPCClient{client: recordingv1.NewVideoRecordingClient(conn), conn: conn}, nil
}

// GetVideoSegment passes through only the identity verified by the Gateway.
func (c *VideoRecorderGRPCClient) GetVideoSegment(ctx context.Context, sessionID string, firstSequence int64, actorID string, roles []string) (*recordingv1.GetVideoSegmentResponse, error) {
	return c.client.GetVideoSegment(ctx, &recordingv1.GetVideoSegmentRequest{
		SessionId: sessionID, FirstSequence: firstSequence,
		ActorUserId: actorID, ActorRoles: roles,
	})
}

// Close releases the gRPC connection.
func (c *VideoRecorderGRPCClient) Close() error { return c.conn.Close() }

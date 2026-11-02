package interfaces

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/proto/recording/v1"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	grpccredentials "google.golang.org/grpc/credentials"
	grpcpeer "google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type GRPCServer struct {
	recordingv1.UnimplementedVideoRecordingServer
	svc *application.RecorderService
}

func NewGRPCServer(svc *application.RecorderService, runtime *mtls.Runtime) *grpc.Server {
	rules := GRPCCallerRules()
	options := []grpc.ServerOption{
		grpc.MaxRecvMsgSize(application.MaxSegmentBytes + (1 << 20)),
		grpc.MaxSendMsgSize(application.MaxSegmentBytes + (1 << 20)),
		grpc.ChainUnaryInterceptor(unaryCallerInterceptor(rules, runtime)),
		grpc.ChainStreamInterceptor(streamCallerInterceptor(rules, runtime)),
	}
	if runtime != nil && runtime.Enabled() {
		options = append(options, grpc.Creds(grpccredentials.NewTLS(runtime.GRPCServerTLS())))
	}
	server := grpc.NewServer(options...)
	recordingv1.RegisterVideoRecordingServer(server, &GRPCServer{svc: svc})
	return server
}

func (s *GRPCServer) StreamVideoSegments(stream grpc.BidiStreamingServer[recordingv1.VideoSegment, recordingv1.VideoSegmentAck]) error {
	var writer *application.RecordingWriter
	defer func() {
		if writer != nil {
			writer.Close()
		}
	}()

	var sessionID string
	var through int64
	complete := false
	for {
		message, err := stream.Recv()
		if errors.Is(err, io.EOF) {
			if complete {
				return nil
			}
			return status.Error(codes.FailedPrecondition, "video stream ended without a terminal marker")
		}
		if err != nil {
			log.Printf("video-recorder: receiving video stream failed: %v", err)
			return status.Error(codes.Unavailable, "video stream receive failed")
		}
		if sessionID == "" {
			sessionID = message.GetSessionId()
			writer, err = s.svc.BeginRecording(stream.Context(), sessionID)
			if err != nil {
				return grpcError(err)
			}
		} else if message.GetSessionId() != sessionID {
			return status.Error(codes.InvalidArgument, "video stream session id changed")
		}

		segment, err := videoSegmentFromProto(message)
		if err != nil {
			return status.Error(codes.InvalidArgument, "video segment is invalid")
		}
		if segment.Terminal {
			if segment.TerminalThroughSequence != through {
				return status.Error(codes.FailedPrecondition, "terminal sequence does not match acknowledged segments")
			}
			if err := writer.Complete(stream.Context(), through); err != nil {
				return grpcError(err)
			}
			complete = true
			if err := stream.Send(&recordingv1.VideoSegmentAck{
				SessionId: sessionID, ThroughSequence: through, Complete: true,
			}); err != nil {
				return status.Error(codes.Unavailable, "video stream acknowledgement failed")
			}
			continue
		}
		if complete {
			return status.Error(codes.FailedPrecondition, "video segment received after terminal marker")
		}
		if err := writer.RecordSegment(stream.Context(), segment); err != nil {
			return grpcError(err)
		}
		through = segment.LastSequence
		if err := stream.Send(&recordingv1.VideoSegmentAck{
			SessionId: sessionID, ThroughSequence: through,
		}); err != nil {
			return status.Error(codes.Unavailable, "video stream acknowledgement failed")
		}
	}
}

func (s *GRPCServer) GetVideoSegment(ctx context.Context, request *recordingv1.GetVideoSegmentRequest) (*recordingv1.GetVideoSegmentResponse, error) {
	if request == nil {
		return nil, status.Error(codes.InvalidArgument, "video segment request is required")
	}
	segment, complete, err := s.svc.ReadSegment(ctx, request.GetActorUserId(), request.GetActorRoles(),
		request.GetSessionId(), request.GetFirstSequence())
	if err != nil {
		return nil, grpcError(err)
	}
	response := &recordingv1.GetVideoSegmentResponse{
		SessionId: segment.SessionID, FirstSequence: segment.FirstSequence,
		LastSequence: segment.LastSequence, Complete: complete,
		Frames: make([]*recordingv1.VideoFrameData, 0, len(segment.Frames)),
	}
	for _, frame := range segment.Frames {
		response.Frames = append(response.Frames, &recordingv1.VideoFrameData{
			Ts: timestamppb.New(frame.Timestamp), FrameData: frame.Data, Codec: frame.Codec,
		})
	}
	return response, nil
}

func (s *GRPCServer) CheckReadiness(ctx context.Context, _ *recordingv1.CheckVideoRecorderReadinessRequest) (*recordingv1.CheckVideoRecorderReadinessResponse, error) {
	if err := s.svc.Ready(ctx); err != nil {
		log.Printf("video-recorder: readiness check failed: %v", err)
		return nil, status.Error(codes.Unavailable, "video recorder is not ready")
	}
	return &recordingv1.CheckVideoRecorderReadinessResponse{Ready: true}, nil
}

func videoSegmentFromProto(message *recordingv1.VideoSegment) (domain.VideoSegment, error) {
	if message == nil {
		return domain.VideoSegment{}, domain.ErrInvalidSegment
	}
	segment := domain.VideoSegment{
		SessionID: message.GetSessionId(), FirstSequence: message.GetFirstSequence(),
		LastSequence: message.GetLastSequence(), Terminal: message.GetTerminal(),
		TerminalThroughSequence: message.GetTerminalThroughSequence(),
		Frames:                  make([]domain.VideoFrame, 0, len(message.GetFrames())),
	}
	for _, frame := range message.GetFrames() {
		if frame == nil || frame.GetTs() == nil || frame.GetTs().CheckValid() != nil {
			return domain.VideoSegment{}, domain.ErrInvalidSegment
		}
		segment.Frames = append(segment.Frames, domain.VideoFrame{
			Timestamp: frame.GetTs().AsTime(), Data: frame.GetFrameData(), Codec: frame.GetCodec(),
		})
	}
	if err := application.ValidateSegment(segment); err != nil {
		return domain.VideoSegment{}, err
	}
	return segment, nil
}

func grpcError(err error) error {
	switch {
	case errors.Is(err, domain.ErrInvalidSegment):
		return status.Error(codes.InvalidArgument, "video segment is invalid")
	case errors.Is(err, domain.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, "video recording already exists")
	case errors.Is(err, domain.ErrConflict):
		return status.Error(codes.FailedPrecondition, "video recording sequence conflicts")
	case errors.Is(err, domain.ErrNotFound):
		return status.Error(codes.NotFound, "video segment was not found")
	case errors.Is(err, domain.ErrForbidden):
		return status.Error(codes.PermissionDenied, "video recording access denied")
	case errors.Is(err, domain.ErrIntegrity):
		return status.Error(codes.DataLoss, "video recording integrity check failed")
	case errors.Is(err, domain.ErrUnavailable):
		log.Printf("video-recorder: dependency failure: %v", err)
		return status.Error(codes.Unavailable, "video recorder dependency unavailable")
	default:
		log.Printf("video-recorder: request failed: %v", err)
		return status.Error(codes.Unavailable, "video recorder dependency unavailable")
	}
}

func unaryCallerInterceptor(rules []GRPCRule, runtime *mtls.Runtime) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, request any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
		caller, err := authenticatedCaller(ctx, info.FullMethod, rules, runtime)
		if err != nil {
			return nil, err
		}
		if caller != "" {
			ctx = mtls.WithCaller(ctx, caller)
		}
		return handler(ctx, request)
	}
}

func streamCallerInterceptor(rules []GRPCRule, runtime *mtls.Runtime) grpc.StreamServerInterceptor {
	return func(server any, stream grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		caller, err := authenticatedCaller(stream.Context(), info.FullMethod, rules, runtime)
		if err != nil {
			return err
		}
		if caller != "" {
			stream = callerServerStream{ServerStream: stream, ctx: mtls.WithCaller(stream.Context(), caller)}
		}
		return handler(server, stream)
	}
}

func authenticatedCaller(ctx context.Context, method string, rules []GRPCRule, runtime *mtls.Runtime) (string, error) {
	var allowed []string
	for _, rule := range rules {
		if rule.Method == method {
			allowed = rule.Callers
			break
		}
	}
	if len(allowed) == 0 {
		return "", status.Error(codes.PermissionDenied, "RPC method is not enabled")
	}
	if runtime == nil || !runtime.Enabled() {
		return "", nil
	}
	caller, err := grpcPeerCaller(ctx, runtime.Credentials().TrustDomain())
	if err != nil {
		return "", status.Error(codes.Unauthenticated, "service identity is required")
	}
	for _, permitted := range allowed {
		if permitted == mtls.Any || permitted == caller {
			return caller, nil
		}
	}
	log.Printf("video-recorder: refused RPC %s from %q: caller is not allowed", method, caller)
	return "", status.Error(codes.PermissionDenied, "service caller is not allowed")
}

func grpcPeerCaller(ctx context.Context, trustDomain string) (string, error) {
	remote, ok := grpcpeer.FromContext(ctx)
	if !ok || remote.AuthInfo == nil {
		return "", mtls.ErrNoIdentity
	}
	var state *tls.ConnectionState
	switch auth := remote.AuthInfo.(type) {
	case grpccredentials.TLSInfo:
		state = &auth.State
	case *grpccredentials.TLSInfo:
		if auth != nil {
			state = &auth.State
		}
	}
	if state == nil || len(state.VerifiedChains) == 0 || len(state.PeerCertificates) == 0 {
		return "", mtls.ErrNoIdentity
	}
	return mtls.ServiceFromCertificate(state.PeerCertificates[0], trustDomain)
}

type callerServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s callerServerStream) Context() context.Context { return s.ctx }

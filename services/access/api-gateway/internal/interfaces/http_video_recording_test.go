package interfaces_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	grpccodes "google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fakeVideoRecorder struct {
	calls         int
	sessionID     string
	firstSequence int64
	actorID       string
	roles         []string
	hasDeadline   bool
	response      *recordingv1.GetVideoSegmentResponse
	err           error
}

func (f *fakeVideoRecorder) GetVideoSegment(ctx context.Context, sessionID string, firstSequence int64, actorID string, roles []string) (*recordingv1.GetVideoSegmentResponse, error) {
	f.calls++
	f.sessionID, f.firstSequence, f.actorID = sessionID, firstSequence, actorID
	f.roles = append([]string(nil), roles...)
	_, f.hasDeadline = ctx.Deadline()
	return f.response, f.err
}

func TestVideoRecordingRoute_FailsClosedWhenRecorderIsNotConfigured(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"auditor"})
	t.Cleanup(authSrv.Close)
	gateway := newTestGateway(t, authSrv.URL, "")
	request := httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/1", nil)
	request.Header.Set("Authorization", "Bearer tok-alice")
	response := httptest.NewRecorder()

	gateway.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusServiceUnavailable {
		t.Fatalf("route without a configured Video Recorder returned %d, want 503", response.Code)
	}
}

func TestVideoRecordingRoute_ForwardsVerifiedIdentityAndReturnsSegment(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor", "session-reader"})
	t.Cleanup(authSrv.Close)
	recorder := &fakeVideoRecorder{response: validVideoSegmentResponse("s-1", 7)}
	gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(recorder)
	request := httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/7", nil)
	request.Header.Set("Authorization", "Bearer tok-alice")
	response := httptest.NewRecorder()

	gateway.Routes().ServeHTTP(response, request)

	if response.Code != http.StatusOK {
		t.Fatalf("video replay returned %d: %s", response.Code, response.Body.String())
	}
	if recorder.calls != 1 || recorder.sessionID != "s-1" || recorder.firstSequence != 7 ||
		recorder.actorID != "u-verified" || len(recorder.roles) != 2 ||
		recorder.roles[0] != "auditor" || recorder.roles[1] != "session-reader" || !recorder.hasDeadline {
		t.Fatalf("Video Recorder got calls=%d session=%q sequence=%d actor=%q roles=%v deadline=%t",
			recorder.calls, recorder.sessionID, recorder.firstSequence, recorder.actorID, recorder.roles, recorder.hasDeadline)
	}
	if response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("video replay security headers are missing: %v", response.Header())
	}
	var body struct {
		SessionID     string `json:"sessionId"`
		FirstSequence int64  `json:"firstSequence"`
		LastSequence  int64  `json:"lastSequence"`
		Complete      bool   `json:"complete"`
		Frames        []struct {
			Timestamp time.Time `json:"timestamp"`
			FrameData []byte    `json:"frameData"`
			Codec     string    `json:"codec"`
		} `json:"frames"`
	}
	if err := json.NewDecoder(response.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.SessionID != "s-1" || body.FirstSequence != 7 || body.LastSequence != 7 ||
		!body.Complete || len(body.Frames) != 1 || body.Frames[0].Codec != "png" ||
		string(body.Frames[0].FrameData) != "png-data" {
		t.Fatalf("unexpected video replay response: %+v", body)
	}
}

func TestVideoRecordingRoute_RejectsClientIdentityClaims(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor"})
	t.Cleanup(authSrv.Close)
	recorder := &fakeVideoRecorder{response: validVideoSegmentResponse("s-1", 1)}
	gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(recorder).Routes()

	for _, request := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/1?actorUserId=u-victim&actorRoles=platform-admin", nil),
		httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/1", strings.NewReader(`{"actorUserId":"u-victim","actorRoles":["platform-admin"]}`)),
	} {
		request.Header.Set("Authorization", "Bearer tok-alice")
		response := httptest.NewRecorder()
		gateway.ServeHTTP(response, request)
		if response.Code != http.StatusBadRequest {
			t.Fatalf("client-supplied identity was not rejected: %d %q", response.Code, response.Body.String())
		}
	}
	if recorder.calls != 0 {
		t.Fatalf("client identity claims reached Video Recorder %d times", recorder.calls)
	}
}

func TestVideoRecordingRoute_RejectsUnauthenticatedAndInvalidRequests(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor"})
	t.Cleanup(authSrv.Close)
	recorder := &fakeVideoRecorder{response: validVideoSegmentResponse("s-1", 1)}
	gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(recorder).Routes()

	for _, test := range []struct {
		name   string
		method string
		path   string
		token  bool
		want   int
	}{
		{name: "missing token", method: http.MethodGet, path: "/sessions/s-1/recording/video/segments/1", want: http.StatusUnauthorized},
		{name: "wrong method", method: http.MethodPost, path: "/sessions/s-1/recording/video/segments/1", token: true, want: http.StatusMethodNotAllowed},
		{name: "zero sequence", method: http.MethodGet, path: "/sessions/s-1/recording/video/segments/0", token: true, want: http.StatusBadRequest},
		{name: "negative sequence", method: http.MethodGet, path: "/sessions/s-1/recording/video/segments/-1", token: true, want: http.StatusBadRequest},
		{name: "non-numeric sequence", method: http.MethodGet, path: "/sessions/s-1/recording/video/segments/nope", token: true, want: http.StatusBadRequest},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(test.method, test.path, nil)
			if test.token {
				request.Header.Set("Authorization", "Bearer tok-alice")
			}
			response := httptest.NewRecorder()
			gateway.ServeHTTP(response, request)
			if response.Code != test.want {
				t.Fatalf("request returned %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
		})
	}
	if recorder.calls != 0 {
		t.Fatalf("invalid requests reached Video Recorder %d times", recorder.calls)
	}
}

func TestVideoRecordingRoute_MapsRecorderErrorsWithoutLeakingDetails(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want int
	}{
		{name: "forbidden", err: status.Error(grpccodes.PermissionDenied, "internal authorization detail"), want: http.StatusForbidden},
		{name: "missing segment", err: status.Error(grpccodes.NotFound, "internal storage key"), want: http.StatusNotFound},
		{name: "invalid request", err: status.Error(grpccodes.InvalidArgument, "internal validation detail"), want: http.StatusBadRequest},
		{name: "state conflict", err: status.Error(grpccodes.FailedPrecondition, "internal state detail"), want: http.StatusConflict},
		{name: "dependency unavailable", err: status.Error(grpccodes.Unavailable, "internal database address"), want: http.StatusServiceUnavailable},
		{name: "unexpected failure", err: errors.New("internal database address"), want: http.StatusBadGateway},
	} {
		t.Run(test.name, func(t *testing.T) {
			authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor"})
			t.Cleanup(authSrv.Close)
			recorder := &fakeVideoRecorder{err: test.err}
			gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(recorder).Routes()
			request := httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/1", nil)
			request.Header.Set("Authorization", "Bearer tok-alice")
			response := httptest.NewRecorder()

			gateway.ServeHTTP(response, request)

			if response.Code != test.want {
				t.Fatalf("request returned %d, want %d: %s", response.Code, test.want, response.Body.String())
			}
			if strings.Contains(response.Body.String(), "internal") || strings.Contains(response.Body.String(), "address") {
				t.Fatalf("internal error leaked in response: %q", response.Body.String())
			}
		})
	}
}

func TestVideoRecordingRoute_RejectsMalformedRecorderSegments(t *testing.T) {
	invalidTimestamp := timestamppb.New(time.Now())
	invalidTimestamp.Seconds = 253402300800
	for _, test := range []struct {
		name     string
		response *recordingv1.GetVideoSegmentResponse
	}{
		{name: "nil response"},
		{name: "wrong session", response: validVideoSegmentResponse("s-other", 1)},
		{name: "wrong sequence bounds", response: validVideoSegmentResponse("s-1", 2)},
		{name: "unsupported codec", response: segmentResponseWithFrame("s-1", 1, &recordingv1.VideoFrameData{Ts: timestamppb.Now(), FrameData: []byte("data"), Codec: "jpeg"})},
		{name: "invalid timestamp", response: segmentResponseWithFrame("s-1", 1, &recordingv1.VideoFrameData{Ts: invalidTimestamp, FrameData: []byte("data"), Codec: "png"})},
		{name: "empty frame", response: segmentResponseWithFrame("s-1", 1, &recordingv1.VideoFrameData{Ts: timestamppb.Now(), Codec: "png"})},
		{name: "oversized frame", response: segmentResponseWithFrame("s-1", 1, &recordingv1.VideoFrameData{Ts: timestamppb.Now(), FrameData: make([]byte, (4<<20)+1), Codec: "png"})},
		{name: "oversized segment", response: &recordingv1.GetVideoSegmentResponse{
			SessionId: "s-1", FirstSequence: 1, LastSequence: 2,
			Frames: []*recordingv1.VideoFrameData{
				{Ts: timestamppb.New(time.Now()), FrameData: make([]byte, 2<<20), Codec: "png"},
				{Ts: timestamppb.New(time.Now()), FrameData: make([]byte, (2<<20)+1), Codec: "png"},
			},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor"})
			t.Cleanup(authSrv.Close)
			recorder := &fakeVideoRecorder{response: test.response}
			gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(recorder).Routes()
			request := httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/1", nil)
			request.Header.Set("Authorization", "Bearer tok-alice")
			response := httptest.NewRecorder()

			gateway.ServeHTTP(response, request)

			if response.Code != http.StatusBadGateway {
				t.Fatalf("malformed segment returned %d, want 502", response.Code)
			}
		})
	}
}

func validVideoSegmentResponse(sessionID string, sequence int64) *recordingv1.GetVideoSegmentResponse {
	return segmentResponseWithFrame(sessionID, sequence, &recordingv1.VideoFrameData{
		Ts:        timestamppb.New(time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)),
		FrameData: []byte("png-data"), Codec: "png",
	})
}

func segmentResponseWithFrame(sessionID string, sequence int64, frame *recordingv1.VideoFrameData) *recordingv1.GetVideoSegmentResponse {
	return &recordingv1.GetVideoSegmentResponse{
		SessionId: sessionID, FirstSequence: sequence, LastSequence: sequence,
		Frames: []*recordingv1.VideoFrameData{frame}, Complete: true,
	}
}

// A partial frame (ADR-0092) is served as the Recorder gave it: the FRAME_DELTA message of its own
// sequence, under codec png-delta-v1. Anything that is not that is refused, as a bad PNG is.
func TestVideoRecordingRoute_ServesPartialFrames(t *testing.T) {
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	delta := func(sequence uint64) []byte {
		data, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: sequence, Timestamp: at,
			Width: 8, Height: 4, Rects: []screenstream.Rect{{Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nrect")}}})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	serve := func(response *recordingv1.GetVideoSegmentResponse) *httptest.ResponseRecorder {
		authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-verified", "alice", []string{"auditor"})
		t.Cleanup(authSrv.Close)
		gateway := newTestGateway(t, authSrv.URL, "").WithVideoRecorderClient(&fakeVideoRecorder{response: response}).Routes()
		request := httptest.NewRequest(http.MethodGet, "/sessions/s-1/recording/video/segments/5", nil)
		request.Header.Set("Authorization", "Bearer tok-alice")
		recorder := httptest.NewRecorder()
		gateway.ServeHTTP(recorder, request)
		return recorder
	}
	good := serve(segmentResponseWithFrame("s-1", 5, &recordingv1.VideoFrameData{Ts: timestamppb.New(at), FrameData: delta(5), Codec: "png-delta-v1"}))
	if good.Code != http.StatusOK {
		t.Fatalf("a segment with a partial frame returned %d: %s", good.Code, good.Body.String())
	}
	var body struct {
		Frames []struct {
			FrameData []byte `json:"frameData"`
			Codec     string `json:"codec"`
		} `json:"frames"`
	}
	if err := json.NewDecoder(good.Body).Decode(&body); err != nil || len(body.Frames) != 1 ||
		body.Frames[0].Codec != "png-delta-v1" || string(body.Frames[0].FrameData) != string(delta(5)) {
		t.Fatalf("the partial frame was not served as the Recorder gave it: %+v %v", body, err)
	}
	for name, frame := range map[string]*recordingv1.VideoFrameData{
		"a partial frame of another sequence": {Ts: timestamppb.New(at), FrameData: delta(6), Codec: "png-delta-v1"},
		"not a partial frame":                 {Ts: timestamppb.New(at), FrameData: []byte("png-data"), Codec: "png-delta-v1"},
		"a key frame under the partial codec": {Ts: timestamppb.New(at), FrameData: keyFrameMessage(t, 5, at), Codec: "png-delta-v1"},
	} {
		if got := serve(segmentResponseWithFrame("s-1", 5, frame)); got.Code != http.StatusBadGateway {
			t.Errorf("%s: %d, want 502", name, got.Code)
		}
	}
}

func keyFrameMessage(t *testing.T, sequence uint64, at time.Time) []byte {
	t.Helper()
	data, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeFrame, Sequence: sequence, Timestamp: at,
		Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nkey")})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

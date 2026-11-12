package application_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/infrastructure"
)

type objectStore struct {
	mu        sync.Mutex
	objects   map[string][]byte
	gets      int
	beforeGet func()
	errPut    error
	errGet    error
}

func newObjectStore() *objectStore {
	return &objectStore{objects: make(map[string][]byte)}
}

func (s *objectStore) Put(_ context.Context, key string, ciphertext []byte) error {
	if s.errPut != nil {
		return s.errPut
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.objects[key] = append([]byte(nil), ciphertext...)
	return nil
}

func (s *objectStore) Get(_ context.Context, key string) ([]byte, error) {
	if s.beforeGet != nil {
		s.beforeGet()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gets++
	if s.errGet != nil {
		return nil, s.errGet
	}
	value, ok := s.objects[key]
	if !ok {
		return nil, errors.New("object missing")
	}
	return append([]byte(nil), value...), nil
}

func (*objectStore) Ready(context.Context) error { return nil }

type authorization struct {
	allowed  bool
	err      error
	resource string
	action   string
}

func (a *authorization) CheckAccess(_ context.Context, _ []string, resource, action string) (bool, string, error) {
	a.resource, a.action = resource, action
	return a.allowed, "", a.err
}

type auditEvent struct {
	actor, action, resourceType, resourceID string
	success                                 bool
}

type auditEmitter struct {
	events  []auditEvent
	details []map[string]string
	err     error
}

func (a *auditEmitter) EmitEvent(_ context.Context, actor, action, resourceType, resourceID string, success bool, details map[string]string) error {
	if a.err != nil {
		return a.err
	}
	a.events = append(a.events, auditEvent{actor, action, resourceType, resourceID, success})
	a.details = append(a.details, details)
	return nil
}

func newRecorder(t *testing.T, authz *authorization, audit *auditEmitter, objects *objectStore) *application.RecorderService {
	t.Helper()
	kek, err := infrastructure.NewLocalKEKFromHexKey(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	return application.NewRecorderService(infrastructure.NewMemoryStore(), objects, kek, authz, audit)
}

func oneFrameSegment(sessionID string, sequence int64) domain.VideoSegment {
	return domain.VideoSegment{
		SessionID: sessionID, FirstSequence: sequence, LastSequence: sequence,
		Frames: []domain.VideoFrame{{
			Timestamp: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Data:      testPNG(), Codec: "png",
		}},
	}
}

func testPNG() []byte {
	var out bytes.Buffer
	img := image.NewRGBA(image.Rect(0, 0, 1, 1))
	img.Set(0, 0, color.RGBA{R: 10, G: 20, B: 30, A: 255})
	if err := png.Encode(&out, img); err != nil {
		panic(err)
	}
	return out.Bytes()
}

func recordOne(t *testing.T, svc *application.RecorderService, sessionID string) {
	t.Helper()
	writer, err := svc.BeginRecording(context.Background(), sessionID)
	if err != nil {
		t.Fatalf("BeginRecording: %v", err)
	}
	if err := writer.RecordSegment(context.Background(), oneFrameSegment(sessionID, 1)); err != nil {
		t.Fatalf("RecordSegment: %v", err)
	}
	if err := writer.Complete(context.Background(), 1); err != nil {
		t.Fatalf("Complete: %v", err)
	}
}

func TestValidateSegmentRejectsInvalidImagesSequencesAndBounds(t *testing.T) {
	valid := oneFrameSegment("s1", 1)
	if err := application.ValidateSegment(valid); err != nil {
		t.Fatalf("valid segment rejected: %v", err)
	}

	tests := map[string]domain.VideoSegment{
		"bad PNG": func() domain.VideoSegment {
			segment := oneFrameSegment("s1", 1)
			segment.Frames[0].Data = []byte("not png")
			return segment
		}(),
		"sequence gap": func() domain.VideoSegment {
			segment := oneFrameSegment("s1", 2)
			segment.FirstSequence = 1
			return segment
		}(),
		"unsupported codec": func() domain.VideoSegment {
			segment := oneFrameSegment("s1", 1)
			segment.Frames[0].Codec = "jpeg"
			return segment
		}(),
		"empty session id": func() domain.VideoSegment {
			segment := oneFrameSegment("s1", 1)
			segment.SessionID = ""
			return segment
		}(),
	}
	for name, segment := range tests {
		t.Run(name, func(t *testing.T) {
			if err := application.ValidateSegment(segment); !errors.Is(err, domain.ErrInvalidSegment) {
				t.Fatalf("expected invalid segment error, got %v", err)
			}
		})
	}

	tooManyPixels := oneFrameSegment("s1", 1)
	var imageBytes bytes.Buffer
	if err := png.Encode(&imageBytes, image.NewRGBA(image.Rect(0, 0, 4097, 4097))); err != nil {
		t.Fatal(err)
	}
	tooManyPixels.Frames[0].Data = imageBytes.Bytes()
	if err := application.ValidateSegment(tooManyPixels); !errors.Is(err, domain.ErrInvalidSegment) {
		t.Fatalf("frame above the pixel limit accepted: %v", err)
	}
}

func TestReadSegmentIsAuditedBeforeObjectFetchAndDecryptsStoredSegment(t *testing.T) {
	authz := &authorization{allowed: true}
	audit := &auditEmitter{}
	objects := newObjectStore()
	svc := newRecorder(t, authz, audit, objects)
	recordOne(t, svc, "s1")

	objects.beforeGet = func() {
		if len(audit.events) != 1 {
			t.Errorf("object fetched before audit event: %+v", audit.events)
		}
	}
	got, complete, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if err != nil || !complete || got.SessionID != "s1" || len(got.Frames) != 1 || !bytes.Equal(got.Frames[0].Data, testPNG()) {
		t.Fatalf("ReadSegment: segment=%+v complete=%v err=%v", got, complete, err)
	}
	if authz.resource != "recording:session:s1" || authz.action != "recording:session:read" {
		t.Fatalf("wrong authorization request: %q %q", authz.resource, authz.action)
	}
	want := auditEvent{"u_reader", application.AuditActionRead, "session", "s1", true}
	if len(audit.events) != 1 || audit.events[0] != want {
		t.Fatalf("audit events: %+v, want %+v", audit.events, want)
	}
}

func TestReadSegmentFailsClosedWhenAuditIsUnavailable(t *testing.T) {
	authz := &authorization{allowed: true}
	audit := &auditEmitter{err: errors.New("audit unavailable")}
	objects := newObjectStore()
	svc := newRecorder(t, authz, audit, objects)
	recordOne(t, svc, "s1")

	_, _, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("expected unavailable result, got %v", err)
	}
	if objects.gets != 0 {
		t.Fatalf("object read despite failed audit: %d", objects.gets)
	}
}

func TestReadSegmentDeniesBeforeLookingUpObjects(t *testing.T) {
	authz := &authorization{}
	audit := &auditEmitter{}
	objects := newObjectStore()
	svc := newRecorder(t, authz, audit, objects)
	recordOne(t, svc, "s1")

	_, _, err := svc.ReadSegment(context.Background(), "u_reader", nil, "s1", 1)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("expected forbidden result, got %v", err)
	}
	if objects.gets != 0 || len(audit.events) != 1 || audit.events[0].success {
		t.Fatalf("denied read touched object store or was not audited: gets=%d events=%+v", objects.gets, audit.events)
	}
}

func TestReadSegmentDetectsObjectTampering(t *testing.T) {
	authz := &authorization{allowed: true}
	audit := &auditEmitter{}
	objects := newObjectStore()
	svc := newRecorder(t, authz, audit, objects)
	recordOne(t, svc, "s1")

	objects.mu.Lock()
	for key, ciphertext := range objects.objects {
		ciphertext[len(ciphertext)-1] ^= 0xff
		objects.objects[key] = ciphertext
	}
	objects.mu.Unlock()
	_, _, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if !errors.Is(err, domain.ErrIntegrity) {
		t.Fatalf("expected integrity error, got %v", err)
	}
}

func TestReadSegmentFailsClosedWhenAuthorizationIsUnavailable(t *testing.T) {
	authz := &authorization{err: errors.New("authorization unavailable")}
	audit := &auditEmitter{}
	objects := newObjectStore()
	svc := newRecorder(t, authz, audit, objects)
	recordOne(t, svc, "s1")

	_, _, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if !errors.Is(err, domain.ErrUnavailable) || len(audit.events) != 0 || objects.gets != 0 {
		t.Fatalf("authorization failure was not fail-closed: err=%v events=%+v gets=%d", err, audit.events, objects.gets)
	}
}

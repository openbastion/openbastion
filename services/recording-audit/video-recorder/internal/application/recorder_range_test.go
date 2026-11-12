package application_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/png"
	"math/rand"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/infrastructure"
)

// A read serves the run of segments from its first (ADR-0093): bounded, verified segment by
// segment, audited once with its range, before anything is fetched.

var rangeAt = time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)

// recordFrames records n one-frame segments, as the proxy does, each PNG made by frame.
func recordFrames(t *testing.T, svc *application.RecorderService, n int, frame func(i int) []byte) {
	t.Helper()
	writer, err := svc.BeginRecording(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= n; i++ {
		segment := domain.VideoSegment{SessionID: "s1", FirstSequence: int64(i), LastSequence: int64(i),
			Frames: []domain.VideoFrame{{Timestamp: rangeAt.Add(time.Duration(i) * time.Millisecond), Data: frame(i), Codec: application.CodecPNG}}}
		if err := writer.RecordSegment(context.Background(), segment); err != nil {
			t.Fatalf("segment %d: %v", i, err)
		}
	}
	if err := writer.Complete(context.Background(), int64(n)); err != nil {
		t.Fatal(err)
	}
}

func smallPNG(int) []byte { return testPNG() }

func read(t *testing.T, svc *application.RecorderService, first int64) (domain.VideoSegment, error) {
	t.Helper()
	segment, _, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", first)
	return segment, err
}

func TestAReadServesTheRunFromItsFirstSegmentAuditedOnce(t *testing.T) {
	audit := &auditEmitter{}
	objects := newObjectStore()
	svc := newRecorder(t, &authorization{allowed: true}, audit, objects)
	recordFrames(t, svc, 10, smallPNG)
	objects.beforeGet = func() {
		if len(audit.events) != 1 {
			t.Errorf("an object fetched before the read was audited: %d event(s)", len(audit.events))
		}
	}
	got, err := read(t, svc, 1)
	if err != nil || got.FirstSequence != 1 || got.LastSequence != 10 || len(got.Frames) != 10 {
		t.Fatalf("read from 1: %d..%d, %d frame(s), %v", got.FirstSequence, got.LastSequence, len(got.Frames), err)
	}
	if len(audit.events) != 1 || audit.details[0]["first_sequence"] != "1" || audit.details[0]["last_sequence"] != "10" {
		t.Fatalf("audit: %d event(s), details %v; want one, naming 1..10", len(audit.events), audit.details)
	}
	objects.beforeGet = nil
	got, err = read(t, svc, 4)
	if err != nil || got.FirstSequence != 4 || got.LastSequence != 10 || len(got.Frames) != 7 {
		t.Fatalf("read from 4: %d..%d, %d frame(s), %v", got.FirstSequence, got.LastSequence, len(got.Frames), err)
	}
	for i, frame := range got.Frames {
		if !frame.Timestamp.Equal(rangeAt.Add(time.Duration(i+4) * time.Millisecond)) {
			t.Fatalf("frame %d is not frame %d", i, i+4)
		}
	}
	audit.events, audit.details = nil, nil
	if _, err := read(t, svc, 11); !errors.Is(err, domain.ErrNotFound) || len(audit.events) != 0 {
		t.Fatalf("past the end: %v, %d audit event(s)", err, len(audit.events))
	}
}

func TestAReadStopsAtSixHundredFrames(t *testing.T) {
	svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, newObjectStore())
	recordFrames(t, svc, application.MaxReadFrames+5, smallPNG)
	got, err := read(t, svc, 1)
	if err != nil || len(got.Frames) != application.MaxReadFrames || got.LastSequence != int64(application.MaxReadFrames) {
		t.Fatalf("first read: %d frame(s) to %d, %v", len(got.Frames), got.LastSequence, err)
	}
	rest, err := read(t, svc, got.LastSequence+1)
	if err != nil || len(rest.Frames) != 5 || rest.LastSequence != int64(application.MaxReadFrames+5) {
		t.Fatalf("second read: %d frame(s) to %d, %v", len(rest.Frames), rest.LastSequence, err)
	}
}

// noisePNG is a PNG that does not compress: about 4 bytes a pixel.
func noisePNG(t *testing.T, w, h int, seed int64) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	rand.New(rand.NewSource(seed)).Read(img.Pix)
	for i := 3; i < len(img.Pix); i += 4 {
		img.Pix[i] = 0xff
	}
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func TestAReadStopsBeforeFourMebibytes(t *testing.T) {
	svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, newObjectStore())
	frames := map[int][]byte{}
	recordFrames(t, svc, 3, func(i int) []byte {
		frames[i] = noisePNG(t, 720, 720, int64(i)) // about 2 MiB each: two fit in 4 MiB, three do not
		return frames[i]
	})
	if size := len(frames[1]) + len(frames[2]) + len(frames[3]); size <= application.MaxReadBytes {
		t.Fatalf("the test's frames weigh %d bytes together: not past the bound", size)
	}
	got, err := read(t, svc, 1)
	if err != nil || len(got.Frames) != 2 || got.LastSequence != 2 {
		t.Fatalf("read: %d frame(s) to %d, %v; want the two that fit in 4 MiB", len(got.Frames), got.LastSequence, err)
	}
}

// gapRepository drops one segment from the runs it returns, as if it were missing.
type gapRepository struct {
	domain.Repository
	missing int64
}

func (g gapRepository) GetSegmentsFrom(ctx context.Context, sessionID string, first int64, limit int) ([]domain.StoredSegment, error) {
	all, err := g.Repository.GetSegmentsFrom(ctx, sessionID, first, limit)
	var out []domain.StoredSegment
	for _, s := range all {
		if s.FirstSequence != g.missing {
			out = append(out, s)
		}
	}
	return out, err
}

func TestAReadStopsAtAGapAndRefusesACorruptSegment(t *testing.T) {
	kek, err := infrastructure.NewLocalKEKFromHexKey("abababababababababababababababababababababababababababababababab")
	if err != nil {
		t.Fatal(err)
	}
	repo := infrastructure.NewMemoryStore()
	objects := newObjectStore()
	writer := application.NewRecorderService(repo, objects, kek, &authorization{allowed: true}, &auditEmitter{})
	recordFrames(t, writer, 6, smallPNG)

	gapped := application.NewRecorderService(gapRepository{Repository: repo, missing: 4}, objects, kek, &authorization{allowed: true}, &auditEmitter{})
	got, _, err := gapped.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if err != nil || got.LastSequence != 3 || len(got.Frames) != 3 {
		t.Fatalf("a run with a gap after 3: %d..%d, %v", got.FirstSequence, got.LastSequence, err)
	}

	// A segment in the middle of the run tampered with: the whole answer is refused.
	stored, err := repo.GetSegment(context.Background(), "s1", 4)
	if err != nil {
		t.Fatal(err)
	}
	objects.mu.Lock()
	objects.objects[stored.ObjectKey][len(objects.objects[stored.ObjectKey])-1] ^= 1
	objects.mu.Unlock()
	if got, err := read(t, writer, 1); !errors.Is(err, domain.ErrIntegrity) || len(got.Frames) != 0 {
		t.Fatalf("a corrupt segment 4 in 1..6: %d frame(s), %v; want nothing and ErrIntegrity", len(got.Frames), err)
	}
	if got, err := read(t, writer, 5); err != nil || got.FirstSequence != 5 || got.LastSequence != 6 {
		t.Fatalf("after the corrupt segment: %d..%d, %v", got.FirstSequence, got.LastSequence, err)
	}
}

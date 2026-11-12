package application_test

import (
	"bytes"
	"context"
	"errors"
	"image"
	"image/color"
	"image/png"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

// Partial frames in the Recorder (ADR-0092, increment 3): validated, stored, read back as written.

var partialAt = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func sizedPNG(t *testing.T, w, h int) []byte {
	t.Helper()
	img := image.NewRGBA(image.Rect(0, 0, w, h))
	img.Set(0, 0, color.RGBA{R: 200, A: 255})
	var out bytes.Buffer
	if err := png.Encode(&out, img); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func keyFrame(t *testing.T, w, h int, at time.Time) domain.VideoFrame {
	return domain.VideoFrame{Timestamp: at, Data: sizedPNG(t, w, h), Codec: application.CodecPNG}
}

func deltaFrame(t *testing.T, sequence uint64, w, h uint32, at time.Time, rects ...screenstream.Rect) domain.VideoFrame {
	t.Helper()
	if rects == nil {
		rects = []screenstream.Rect{{X: 0, Y: 0, Width: 1, Height: 1, PNG: sizedPNG(t, 1, 1)}}
	}
	data, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: sequence, Timestamp: at,
		Width: w, Height: h, Rects: rects})
	if err != nil {
		t.Fatal(err)
	}
	return domain.VideoFrame{Timestamp: at, Data: data, Codec: application.CodecPNGDelta}
}

func segmentOf(sessionID string, first int64, frames ...domain.VideoFrame) domain.VideoSegment {
	return domain.VideoSegment{SessionID: sessionID, FirstSequence: first, LastSequence: first + int64(len(frames)) - 1, Frames: frames}
}

func TestPartialFramesAreRecordedAndReadBackAsWritten(t *testing.T) {
	svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, newObjectStore())
	writer, err := svc.BeginRecording(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	key := segmentOf("s1", 1, keyFrame(t, 8, 4, partialAt))
	// The key frame in one segment, its partial frames in the next: the screen carries over.
	partial := segmentOf("s1", 2, deltaFrame(t, 2, 8, 4, partialAt), deltaFrame(t, 3, 8, 4, partialAt.Add(time.Millisecond)))
	for _, segment := range []domain.VideoSegment{key, partial} {
		if err := writer.RecordSegment(context.Background(), segment); err != nil {
			t.Fatalf("sequence %d: %v", segment.FirstSequence, err)
		}
	}
	if err := writer.Complete(context.Background(), 3); err != nil {
		t.Fatal(err)
	}
	for _, want := range []domain.VideoSegment{key, partial} {
		got, complete, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", want.FirstSequence)
		if err != nil || !complete || len(got.Frames) != len(want.Frames) {
			t.Fatalf("segment %d: %+v %v %v", want.FirstSequence, got, complete, err)
		}
		for i := range want.Frames {
			if got.Frames[i].Codec != want.Frames[i].Codec || !bytes.Equal(got.Frames[i].Data, want.Frames[i].Data) {
				t.Fatalf("segment %d, frame %d is not what was written", want.FirstSequence, i)
			}
		}
	}
}

func TestPartialFrameWithoutItsScreenIsRefused(t *testing.T) {
	cases := map[string][]domain.VideoSegment{
		"before any key frame":            {segmentOf("s1", 1, deltaFrame(t, 1, 8, 4, partialAt))},
		"of another size than its screen": {segmentOf("s1", 1, keyFrame(t, 8, 4, partialAt)), segmentOf("s1", 2, deltaFrame(t, 2, 16, 4, partialAt))},
		"after a resize, of the old size": {segmentOf("s1", 1, keyFrame(t, 8, 4, partialAt), keyFrame(t, 16, 4, partialAt)), segmentOf("s1", 3, deltaFrame(t, 3, 8, 4, partialAt))},
	}
	for name, segments := range cases {
		svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, newObjectStore())
		writer, err := svc.BeginRecording(context.Background(), "s1")
		if err != nil {
			t.Fatal(err)
		}
		var last error
		for _, segment := range segments {
			last = writer.RecordSegment(context.Background(), segment)
		}
		if !errors.Is(last, domain.ErrInvalidSegment) {
			t.Errorf("%s: %v, want ErrInvalidSegment", name, last)
		}
	}
}

func TestValidateSegmentChecksEachPartialFrame(t *testing.T) {
	frame := func(edit func(*domain.VideoFrame)) domain.VideoSegment {
		f := deltaFrame(t, 5, 8, 4, partialAt)
		edit(&f)
		return segmentOf("s1", 5, f)
	}
	keyAsDelta, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeFrame, Sequence: 5, Timestamp: partialAt, Width: 1, Height: 1, PNG: sizedPNG(t, 1, 1)})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]domain.VideoSegment{
		"another sequence":   segmentOf("s1", 6, deltaFrame(t, 5, 8, 4, partialAt)),
		"another time":       frame(func(f *domain.VideoFrame) { f.Timestamp = partialAt.Add(time.Second) }),
		"a key frame inside": frame(func(f *domain.VideoFrame) { f.Data = keyAsDelta }),
		"not a message":      frame(func(f *domain.VideoFrame) { f.Data = []byte("not a frame") }),
		"an unknown codec":   frame(func(f *domain.VideoFrame) { f.Codec = "png-delta-v9" }),
		"a PNG of another size": segmentOf("s1", 5, deltaFrame(t, 5, 8, 4, partialAt,
			screenstream.Rect{X: 0, Y: 0, Width: 2, Height: 1, PNG: sizedPNG(t, 1, 1)})),
		"a rectangle that is no PNG": segmentOf("s1", 5, deltaFrame(t, 5, 8, 4, partialAt,
			screenstream.Rect{X: 0, Y: 0, Width: 1, Height: 1, PNG: append([]byte("\x89PNG\r\n\x1a\n"), 1, 2, 3)})),
	}
	for name, segment := range cases {
		if err := application.ValidateSegment(segment); !errors.Is(err, domain.ErrInvalidSegment) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if err := application.ValidateSegment(segmentOf("s1", 5, deltaFrame(t, 5, 8, 4, partialAt))); err != nil {
		t.Fatalf("a well-formed partial frame: %v", err)
	}
}

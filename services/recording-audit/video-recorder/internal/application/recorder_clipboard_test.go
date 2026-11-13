package application_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

// Clipboard texts in the Recorder (ADR-0096, increment 3): in the sequence of the frames, stored
// encrypted, read back as written.

func clipboardEntry(t *testing.T, sequence uint64, direction screenstream.ClipboardDirection, text string, at time.Time) domain.VideoFrame {
	t.Helper()
	data, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeClipboard, Sequence: sequence, Timestamp: at,
		Direction: direction, ClipboardText: text})
	if err != nil {
		t.Fatal(err)
	}
	return domain.VideoFrame{Timestamp: at, Data: data, Codec: application.CodecClipboardText}
}

// A text pasted and a text copied, between frames: recorded, read back as written, and a partial
// frame after them still applies to the screen of the key frame before them.
func TestClipboardTextsAreRecordedAndReadBackAsWritten(t *testing.T) {
	objects := newObjectStore()
	svc := newRecorder(t, &authorization{allowed: true}, &auditEmitter{}, objects)
	writer, err := svc.BeginRecording(context.Background(), "s1")
	if err != nil {
		t.Fatal(err)
	}
	segments := []domain.VideoSegment{
		segmentOf("s1", 1, keyFrame(t, 8, 4, partialAt), clipboardEntry(t, 2, screenstream.ClipboardToTarget, "pasted é €", partialAt)),
		segmentOf("s1", 3, clipboardEntry(t, 3, screenstream.ClipboardFromTarget, "copied\r\nlines", partialAt.Add(time.Millisecond)),
			deltaFrame(t, 4, 8, 4, partialAt.Add(2*time.Millisecond))),
	}
	for _, segment := range segments {
		if err := writer.RecordSegment(context.Background(), segment); err != nil {
			t.Fatalf("sequence %d: %v", segment.FirstSequence, err)
		}
	}
	if err := writer.Complete(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	got, complete, err := svc.ReadSegment(context.Background(), "u_reader", []string{"auditor"}, "s1", 1)
	if err != nil || !complete || len(got.Frames) != 4 {
		t.Fatalf("read: %d frame(s), %v %v", len(got.Frames), complete, err)
	}
	want := append(append([]domain.VideoFrame(nil), segments[0].Frames...), segments[1].Frames...)
	for i := range want {
		if got.Frames[i].Codec != want[i].Codec || !bytes.Equal(got.Frames[i].Data, want[i].Data) {
			t.Fatalf("frame %d is not what was written", i)
		}
	}
	// The text is in the encrypted segment, never in clear in the store.
	objects.mu.Lock()
	defer objects.mu.Unlock()
	if len(objects.objects) == 0 {
		t.Fatal("nothing stored")
	}
	for key, object := range objects.objects {
		if bytes.Contains(object, []byte("pasted")) || bytes.Contains(object, []byte("copied")) {
			t.Fatalf("object %s holds a clipboard text in clear", key)
		}
	}
}

// A clipboard entry that is not the CLIPBOARD message of its own sequence and time is refused, and
// so is a CLIPBOARD message under another codec.
func TestClipboardEntryOutOfItsPlaceIsRefused(t *testing.T) {
	other := clipboardEntry(t, 5, screenstream.ClipboardToTarget, "x", partialAt)
	late := clipboardEntry(t, 2, screenstream.ClipboardToTarget, "x", partialAt)
	late.Timestamp = partialAt.Add(time.Millisecond)
	asKey := clipboardEntry(t, 2, screenstream.ClipboardToTarget, "x", partialAt)
	asKey.Codec = application.CodecPNG
	frameAsClip := keyFrame(t, 8, 4, partialAt)
	frameAsClip.Codec = application.CodecClipboardText
	unknown := clipboardEntry(t, 2, screenstream.ClipboardToTarget, "x", partialAt)
	unknown.Codec = "clipboard-text-v9"
	for name, entry := range map[string]domain.VideoFrame{
		"of another sequence":           other,
		"of another time":               late,
		"under the key frame codec":     asKey,
		"a PNG under the clipboard one": frameAsClip,
		"an unknown codec":              unknown,
	} {
		segment := segmentOf("s1", 1, keyFrame(t, 8, 4, partialAt), entry)
		if err := application.ValidateSegment(segment); !errors.Is(err, domain.ErrInvalidSegment) {
			t.Errorf("%s: %v, want ErrInvalidSegment", name, err)
		}
	}
}

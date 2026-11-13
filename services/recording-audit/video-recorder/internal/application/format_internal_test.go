package application

import (
	"bytes"
	"encoding/json"
	"errors"
	"image"
	"image/png"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
)

// A segment opens only under the format its frames call for, even sealed with the right key
// (ADR-0092 §5): key frames sealed as format 2 are refused, and so are partial frames sealed as
// format 1. Each, sealed as it should be, opens.
func TestASegmentOpensOnlyUnderItsOwnFormat(t *testing.T) {
	dek := bytes.Repeat([]byte{7}, 32)
	at := time.Date(2026, 11, 12, 0, 0, 0, 0, time.UTC)
	var keyPNG, rectPNG bytes.Buffer
	if err := png.Encode(&keyPNG, image.NewRGBA(image.Rect(0, 0, 2, 2))); err != nil {
		t.Fatal(err)
	}
	if err := png.Encode(&rectPNG, image.NewRGBA(image.Rect(0, 0, 1, 1))); err != nil {
		t.Fatal(err)
	}
	delta, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeFrameDelta, Sequence: 1, Timestamp: at,
		Width: 2, Height: 2, Rects: []screenstream.Rect{{Width: 1, Height: 1, PNG: rectPNG.Bytes()}}})
	if err != nil {
		t.Fatal(err)
	}
	keys := domain.VideoSegment{SessionID: "s1", FirstSequence: 1, LastSequence: 1,
		Frames: []domain.VideoFrame{{Timestamp: at, Data: keyPNG.Bytes(), Codec: CodecPNG}}}
	partial := domain.VideoSegment{SessionID: "s1", FirstSequence: 1, LastSequence: 1,
		Frames: []domain.VideoFrame{{Timestamp: at, Data: delta, Codec: CodecPNGDelta}}}
	clip, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeClipboard, Sequence: 2, Timestamp: at,
		Direction: screenstream.ClipboardFromTarget, ClipboardText: "copied"})
	if err != nil {
		t.Fatal(err)
	}
	clipboard := domain.VideoSegment{SessionID: "s1", FirstSequence: 1, LastSequence: 2,
		Frames: []domain.VideoFrame{{Timestamp: at, Data: keyPNG.Bytes(), Codec: CodecPNG}, {Timestamp: at, Data: clip, Codec: CodecClipboardText}}}
	sealAs := func(segment domain.VideoSegment, format string) []byte {
		plain, err := json.Marshal(segment)
		if err != nil {
			t.Fatal(err)
		}
		sealed, err := seal(dek, plain, segmentAAD(format, "s1", segment.FirstSequence, segment.LastSequence))
		if err != nil {
			t.Fatal(err)
		}
		return sealed
	}
	for name, c := range map[string]struct {
		segment domain.VideoSegment
		format  string
		opens   bool
	}{
		"key frames as format 1":       {keys, recordingFormat, true},
		"partial frames as format 2":   {partial, recordingFormatV2, true},
		"key frames as format 2":       {keys, recordingFormatV2, false},
		"partial frames as format 1":   {partial, recordingFormat, false},
		"a clipboard text as format 3": {clipboard, recordingFormatV3, true},
		"a clipboard text as format 1": {clipboard, recordingFormat, false},
		"a clipboard text as format 2": {clipboard, recordingFormatV2, false},
		"key frames as format 3":       {keys, recordingFormatV3, false},
		"partial frames as format 3":   {partial, recordingFormatV3, false},
	} {
		_, err := openSegment(dek, sealAs(c.segment, c.format), "s1", c.segment.FirstSequence, c.segment.LastSequence)
		if c.opens && err != nil {
			t.Errorf("%s: %v", name, err)
		}
		if !c.opens && !errors.Is(err, domain.ErrIntegrity) {
			t.Errorf("%s: %v, want ErrIntegrity", name, err)
		}
	}
	both := partial
	both.LastSequence = 2
	both.Frames = append(append([]domain.VideoFrame(nil), partial.Frames...), clipboard.Frames[1])
	if segmentFormat(keys) != recordingFormat || segmentFormat(partial) != recordingFormatV2 ||
		segmentFormat(clipboard) != recordingFormatV3 || segmentFormat(both) != recordingFormatV3 {
		t.Fatal("a segment's format is not the one its frames call for")
	}
}

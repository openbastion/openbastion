package screenstream

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"
	"time"
)

var testPNG = []byte("\x89PNG\r\n\x1a\n" + "payload")

func TestFrameRoundTrip(t *testing.T) {
	in := Message{Type: TypeFrame, Sequence: 1, Timestamp: time.Unix(100, 42).UTC(), Width: 800, Height: 600, PNG: testPNG}
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	if len(wire) != HeaderSize+len(testPNG) {
		t.Fatalf("wire length = %d", len(wire))
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Sequence != in.Sequence || !got.Timestamp.Equal(in.Timestamp) || got.Width != in.Width || got.Height != in.Height || !bytes.Equal(got.PNG, in.PNG) {
		t.Fatalf("round trip mismatch: got %#v", got)
	}
}

func TestHelloRoundTrip(t *testing.T) {
	in := Message{Type: TypeHello, Sequence: 1, Timestamp: time.Unix(100, 0).UTC(), Protocol: ProtocolVNC, ExpiresAt: time.Unix(200, 0).UTC(), SessionID: "session-1"}
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.Protocol != in.Protocol || !got.ExpiresAt.Equal(in.ExpiresAt) || got.SessionID != in.SessionID {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestEndRoundTrip(t *testing.T) {
	in := Message{Type: TypeEnd, Sequence: 2, Timestamp: time.Unix(100, 0).UTC(), EndCode: 7, Text: "session revoked"}
	wire, err := Encode(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Decode(wire)
	if err != nil {
		t.Fatal(err)
	}
	if got.EndCode != in.EndCode || got.Text != in.Text {
		t.Fatalf("round trip mismatch: %#v", got)
	}
}

func TestDecodeRejectsMalformedAndNonCanonicalFrames(t *testing.T) {
	valid, err := Encode(Message{Type: TypeFrame, Sequence: 1, Timestamp: time.Unix(1, 0), Width: 1, Height: 1, PNG: testPNG})
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string][]byte{
		"truncated":            valid[:HeaderSize-1],
		"trailing":             append(append([]byte(nil), valid...), 0),
		"wrong version":        append([]byte{2}, valid[1:]...),
		"reserved flags":       func() []byte { b := append([]byte(nil), valid...); b[2] = 1; return b }(),
		"wrong payload length": func() []byte { b := append([]byte(nil), valid...); binary.BigEndian.PutUint32(b[28:32], 1); return b }(),
		"bad png":              func() []byte { b := append([]byte(nil), valid...); b[HeaderSize] = 0; return b }(),
	}
	for name, wire := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := Decode(wire); err == nil {
				t.Fatal("malformed message accepted")
			}
		})
	}
}

func TestEncodeRejectsOversizedAndInvalidValues(t *testing.T) {
	cases := []Message{
		{Type: TypeFrame, Sequence: 1, Timestamp: time.Now(), Width: MaxPixels + 1, Height: 1, PNG: testPNG},
		{Type: TypeFrame, Sequence: 1, Timestamp: time.Now(), Width: 1, Height: 1, PNG: bytes.Repeat([]byte("x"), MaxPNGBytes+1)},
		{Type: TypeHello, Protocol: 9, ExpiresAt: time.Now(), SessionID: "s"},
		{Type: TypeHello, Protocol: ProtocolRDP, ExpiresAt: time.Now(), SessionID: strings.Repeat("x", MaxSessionIDBytes+1)},
		{Type: TypeEnd, Text: strings.Repeat("x", MaxEndTextBytes+1)},
	}
	for i, m := range cases {
		if _, err := Encode(m); err == nil {
			t.Errorf("case %d accepted", i)
		}
	}
}

func TestDecodeRejectsUnknownMessageType(t *testing.T) {
	wire := make([]byte, HeaderSize)
	wire[0], wire[1] = Version, 99
	if _, err := Decode(wire); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("error = %v", err)
	}
}

func TestInputRoundTripAndBounds(t *testing.T) {
	in := InputEvent{Type: InputPointer, X: 10, Y: 20, Buttons: 1}
	wire, err := EncodeInput(in)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeInput(wire, 100, 100)
	if err != nil {
		t.Fatal(err)
	}
	if got != in {
		t.Fatalf("got %#v, want %#v", got, in)
	}
	if _, err := DecodeInput(wire, 10, 100); !errors.Is(err, ErrOutOfBounds) {
		t.Fatalf("out of bounds error = %v", err)
	}
}

func TestInputRejectsUnknownTypeAndOversizedMessage(t *testing.T) {
	if _, err := DecodeInput(make([]byte, InputMessageSize+1), 100, 100); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("oversized error = %v", err)
	}
	wire := make([]byte, InputMessageSize)
	wire[0], wire[1] = Version, 99
	if _, err := DecodeInput(wire, 100, 100); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("unknown type error = %v", err)
	}
}

func TestPointerWheelUsesFinalWireByte(t *testing.T) {
	in := InputEvent{Type: InputPointer, X: 1, Y: 2, Wheel: -1}
	wire, err := EncodeInput(in)
	if err != nil {
		t.Fatal(err)
	}
	if got := int8(wire[15]); got != -1 {
		t.Fatalf("wire wheel = %d, want -1", got)
	}
	decoded, err := DecodeInput(wire, 10, 10)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Wheel != -1 {
		t.Fatalf("decoded wheel = %d, want -1", decoded.Wheel)
	}
}

func TestInputRejectsUnexpectedFields(t *testing.T) {
	key, err := EncodeInput(InputEvent{Type: InputKey, Flags: KeyPressed, Keysym: 0x61})
	if err != nil {
		t.Fatal(err)
	}
	key[15] = 1
	if _, err := DecodeInput(key, 100, 100); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("key with wheel data error = %v, want malformed message", err)
	}
	release, err := EncodeInput(InputEvent{Type: InputReleaseAll})
	if err != nil {
		t.Fatal(err)
	}
	release[15] = 1
	if _, err := DecodeInput(release, 100, 100); !errors.Is(err, ErrMalformedMessage) {
		t.Fatalf("release-all with wheel data error = %v, want malformed message", err)
	}
}

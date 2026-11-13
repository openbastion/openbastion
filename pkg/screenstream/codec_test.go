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
	in := Message{Type: TypeHello, Sequence: 0, Timestamp: time.Unix(100, 0).UTC(), Protocol: ProtocolVNC, ExpiresAt: time.Unix(200, 0).UTC(), SessionID: "session-1"}
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

// The pointer flag (ADR-0091): bit 0 of the byte after the protocol, which was reserved and zero.
// A HELLO without it is the HELLO of before; a reserved bit set is still refused.
func TestHelloSaysWhetherThePointerIsDrawn(t *testing.T) {
	for _, drawn := range []bool{false, true} {
		in := Message{Type: TypeHello, Timestamp: time.Unix(100, 0).UTC(), Protocol: ProtocolRDP,
			ExpiresAt: time.Unix(200, 0).UTC(), SessionID: "s", PointerDrawn: drawn}
		wire, err := Encode(in)
		if err != nil {
			t.Fatal(err)
		}
		want := byte(0)
		if drawn {
			want = HelloPointerDrawn
		}
		if wire[HeaderSize+1] != want {
			t.Fatalf("drawn %v: flags byte %#x, want %#x", drawn, wire[HeaderSize+1], want)
		}
		got, err := Decode(wire)
		if err != nil || got.PointerDrawn != drawn {
			t.Fatalf("drawn %v: decoded %v, %v", drawn, got.PointerDrawn, err)
		}
		for _, reserved := range []byte{0x10, 0x80, 0x15} {
			bad := append([]byte(nil), wire...)
			bad[HeaderSize+1] = reserved
			if _, err := Decode(bad); err == nil {
				t.Fatalf("a reserved flag %#x is accepted", reserved)
			}
		}
	}
}

// The HELLO's bit 1 says the session follows InputResize (ADR-0095 §6), next to bit 0.
func TestHelloSaysWhetherTheSessionResizes(t *testing.T) {
	for _, c := range []struct {
		drawn, resizable bool
		flags            byte
	}{{false, false, 0}, {false, true, HelloResizable}, {true, true, HelloPointerDrawn | HelloResizable}} {
		in := Message{Type: TypeHello, Timestamp: time.Unix(100, 0).UTC(), Protocol: ProtocolRDP,
			ExpiresAt: time.Unix(200, 0).UTC(), SessionID: "s", PointerDrawn: c.drawn, Resizable: c.resizable}
		wire, err := Encode(in)
		if err != nil || wire[HeaderSize+1] != c.flags {
			t.Fatalf("%+v: flags %#x, %v", c, wire[HeaderSize+1], err)
		}
		got, err := Decode(wire)
		if err != nil || got.Resizable != c.resizable || got.PointerDrawn != c.drawn {
			t.Fatalf("%+v: decoded %+v, %v", c, got, err)
		}
	}
}

func TestInputResizeCarriesASizeAndNothingElse(t *testing.T) {
	wire, err := EncodeInput(InputEvent{Type: InputResize, X: 1920, Y: 1080})
	if err != nil {
		t.Fatal(err)
	}
	// A size, not a point: a frame smaller than it does not refuse it.
	got, err := DecodeInput(wire, 1280, 800)
	if err != nil || got.Type != InputResize || got.X != 1920 || got.Y != 1080 {
		t.Fatalf("%+v %v", got, err)
	}
	for name, e := range map[string]InputEvent{
		"no width":  {Type: InputResize, X: 0, Y: 1080},
		"no height": {Type: InputResize, X: 1920, Y: 0},
		"a flag":    {Type: InputResize, X: 1920, Y: 1080, Flags: 1},
		"a key":     {Type: InputResize, X: 1920, Y: 1080, Scancode: 0x1e},
		"a keysym":  {Type: InputResize, X: 1920, Y: 1080, Keysym: 0x61},
		"buttons":   {Type: InputResize, X: 1920, Y: 1080, Buttons: 1},
		"a wheel":   {Type: InputResize, X: 1920, Y: 1080, Wheel: 1},
	} {
		raw := make([]byte, InputMessageSize)
		raw[0], raw[1], raw[2] = Version, byte(e.Type), e.Flags
		binary.BigEndian.PutUint32(raw[4:8], e.Keysym)
		binary.BigEndian.PutUint16(raw[8:10], e.Scancode)
		binary.BigEndian.PutUint16(raw[10:12], e.X)
		binary.BigEndian.PutUint16(raw[12:14], e.Y)
		raw[14], raw[15] = e.Buttons, byte(e.Wheel)
		if _, err := DecodeInput(raw, 4000, 4000); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("%s: %v, want refused", name, err)
		}
	}
}

func TestClampResize_KeepsWithinTheBoundsAndEven(t *testing.T) {
	for _, c := range [][4]uint16{
		{1920, 1080, 1920, 1080},
		{1921, 1081, 1920, 1081},
		{100, 100, MinResizeWidth, MinResizeHeight},
		{9000, 9000, MaxResizeWidth, MaxResizeHeight},
		{641, 480, 640, 480},
	} {
		if w, h := ClampResize(c[0], c[1]); w != c[2] || h != c[3] {
			t.Errorf("ClampResize(%d, %d) = %d x %d, want %d x %d", c[0], c[1], w, h, c[2], c[3])
		}
	}
}

// The END codes are part of the v1 contract: their numbers never move, and the code added on
// 13 November 2026 comes after the others.
func TestEndCodesKeepTheirNumbers(t *testing.T) {
	for code, want := range map[uint16]uint16{EndCodeSessionEnded: 0, EndCodeTargetUnreachable: 5, EndCodeRecordingLost: 12, EndCodeTicketInvalid: 13, EndCodeTargetAuthFailed: 14} {
		if code != want {
			t.Errorf("END code %d, want %d", code, want)
		}
	}
}

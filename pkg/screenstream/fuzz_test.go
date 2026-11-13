package screenstream

import (
	"reflect"
	"testing"
	"time"
)

// The browser's and the proxy's side of the screen contract (ADR-0071 §6), under hostile bytes:
// what decodes encodes back to the same message, and nothing panics.
func FuzzDecode(f *testing.F) {
	hello, _ := Encode(Message{Type: TypeHello, Timestamp: time.Unix(1, 0), Protocol: ProtocolRDP, ExpiresAt: time.Unix(2, 0), SessionID: "s1"})
	end, _ := Encode(Message{Type: TypeEnd, Sequence: 1, Timestamp: time.Unix(1, 0), EndCode: EndCodeSessionEnded, Text: "session_ended"})
	f.Add(hello)
	f.Add(end)
	partial, _ := Encode(Message{Type: TypeFrameDelta, Sequence: 2, Timestamp: time.Unix(1, 0), Width: 8, Height: 4,
		Rects: []Rect{{X: 1, Y: 1, Width: 1, Height: 1, PNG: []byte("\x89PNG\r\n\x1a\nIHDR")}}})
	f.Add(partial)
	clipboard, _ := Encode(Message{Type: TypeClipboard, Sequence: 3, Timestamp: time.Unix(1, 0), Direction: ClipboardFromTarget, ClipboardText: "é €\r\n"})
	f.Add(clipboard)
	f.Fuzz(func(t *testing.T, data []byte) {
		m, err := Decode(data)
		if err != nil {
			return
		}
		again, err := Encode(m)
		if err != nil {
			t.Fatalf("decoded %+v does not encode: %v", m, err)
		}
		back, err := Decode(again)
		if err != nil || !reflect.DeepEqual(back, m) {
			t.Fatalf("round trip: %+v, then %+v (%v)", m, back, err)
		}
	})
}

func FuzzDecodeInput(f *testing.F) {
	key, _ := EncodeInput(InputEvent{Type: InputKey, Flags: KeyPressed, Scancode: 0x1e})
	pointer, _ := EncodeInput(InputEvent{Type: InputPointer, X: 3, Y: 2, Buttons: 1})
	f.Add(key, uint32(8), uint32(6))
	f.Add(pointer, uint32(8), uint32(6))
	f.Fuzz(func(t *testing.T, data []byte, width, height uint32) {
		e, err := DecodeInput(data, width, height)
		if err != nil {
			return
		}
		if e.Type == InputPointer && (uint32(e.X) >= width || uint32(e.Y) >= height) {
			t.Fatalf("a pointer at %d,%d outside %dx%d was accepted", e.X, e.Y, width, height)
		}
		again, err := EncodeInput(e)
		if err != nil {
			t.Fatalf("decoded %+v does not encode: %v", e, err)
		}
		back, err := DecodeInput(again, width, height)
		if err != nil || back != e {
			t.Fatalf("round trip: %+v, then %+v (%v)", e, back, err)
		}
	})
}

// The operator's clipboard text, under hostile bytes (ADR-0096 §6): what decodes encodes back to
// the same bytes, within the bound, and nothing panics.
func FuzzDecodeClipboardInput(f *testing.F) {
	good, _ := EncodeClipboardInput("pasted é €")
	f.Add(good)
	f.Add([]byte{Version, byte(InputClipboard), 0, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		text, err := DecodeClipboardInput(data)
		if err != nil {
			return
		}
		again, err := EncodeClipboardInput(text)
		if err != nil || string(again) != string(data) || len(data) > MaxClipboardInputBytes {
			t.Fatalf("decoded %q does not encode back to its bytes: %v", text, err)
		}
	})
}

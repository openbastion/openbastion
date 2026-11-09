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

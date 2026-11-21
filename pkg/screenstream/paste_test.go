package screenstream

import (
	"bytes"
	"errors"
	"testing"
	"time"
)

// ADR-0133: the HELLO carries the proxy's key only with HelloPaste; a HELLO without it is byte for
// byte what it was; an InputPaste reads back exactly and refuses what is out of its bounds.
func TestPaste_TheHelloKeyAndTheInput(t *testing.T) {
	key := append([]byte{0x04}, bytes.Repeat([]byte{7}, PasteKeySize-1)...)
	hello := Message{Type: TypeHello, Timestamp: time.Unix(1, 0), Protocol: ProtocolRDP, SessionID: "sess-1", ExpiresAt: time.Unix(100, 0)}
	plain, err := Encode(hello)
	if err != nil {
		t.Fatal(err)
	}
	hello.PasteKey = key
	withKey, err := Encode(hello)
	if err != nil || len(withKey) != len(plain)+PasteKeySize || withKey[HeaderSize+1]&HelloPaste == 0 || plain[HeaderSize+1]&HelloPaste != 0 {
		t.Fatalf("the HELLO with a key: %d bytes, %v", len(withKey), err)
	}
	back, err := Decode(withKey)
	if err != nil || back.SessionID != "sess-1" || !bytes.Equal(back.PasteKey, key) {
		t.Fatalf("decoded %+v, %v", back, err)
	}
	if back, err := Decode(plain); err != nil || back.PasteKey != nil {
		t.Fatalf("a HELLO without a key: %+v, %v", back, err)
	}
	hello.PasteKey = key[:64]
	if _, err := Encode(hello); err == nil {
		t.Fatal("a short key encoded")
	}
	compressed := append([]byte(nil), withKey...)
	compressed[len(compressed)-PasteKeySize] = 0x02
	if _, err := Decode(compressed); err == nil {
		t.Fatal("a key that is not an uncompressed point decoded")
	}

	in := PasteInput{Ciphertext: bytes.Repeat([]byte{9}, 40)}
	in.Token[0], in.Nonce[11] = 1, 2
	copy(in.ClientKey[:], key)
	raw, err := EncodePasteInput(in)
	if err != nil || !IsPasteInput(raw) || IsClipboardInput(raw) {
		t.Fatalf("encode: %v", err)
	}
	got, err := DecodePasteInput(raw)
	if err != nil || got.Token != in.Token || got.ClientKey != in.ClientKey || got.Nonce != in.Nonce || !bytes.Equal(got.Ciphertext, in.Ciphertext) {
		t.Fatalf("decode: %+v, %v", got, err)
	}
	for name, bad := range map[string][]byte{
		"a byte more":      append(append([]byte(nil), raw...), 0),
		"a byte less":      raw[:len(raw)-1],
		"a reserved byte":  func() []byte { b := append([]byte(nil), raw...); b[2] = 1; return b }(),
		"a compressed key": func() []byte { b := append([]byte(nil), raw...); b[4+PasteTokenSize] = 0x03; return b }(),
		"no ciphertext":    raw[:PasteInputHeader],
		"too long": func() []byte {
			b := append([]byte(nil), raw[:PasteInputHeader]...)
			b[PasteInputHeader-2], b[PasteInputHeader-1] = 0x02, 0x11
			return append(b, make([]byte, 529)...)
		}(),
	} {
		if _, err := DecodePasteInput(bad); !errors.Is(err, ErrMalformedMessage) {
			t.Errorf("%s decoded: %v", name, err)
		}
	}
	if _, err := EncodePasteInput(PasteInput{Ciphertext: make([]byte, MaxPasteCiphertext+1), ClientKey: in.ClientKey}); err == nil {
		t.Fatal("a ciphertext too long encoded")
	}
}

func FuzzDecodePasteInput(f *testing.F) {
	in := PasteInput{Ciphertext: make([]byte, 20)}
	in.ClientKey[0] = 0x04
	raw, _ := EncodePasteInput(in)
	f.Add(raw)
	f.Fuzz(func(t *testing.T, data []byte) {
		got, err := DecodePasteInput(data)
		if err == nil && (len(got.Ciphertext) < minPasteCiphertext || len(got.Ciphertext) > MaxPasteCiphertext || got.ClientKey[0] != 0x04) {
			t.Fatalf("out of bounds: %d", len(got.Ciphertext))
		}
	})
}

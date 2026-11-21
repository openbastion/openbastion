package screenstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"
)

type InputType byte

const (
	InputKey        InputType = 1
	InputPointer    InputType = 2
	InputReleaseAll InputType = 3
	// InputResize asks for the target's desktop at the operator's size (ADR-0095 §5): X is the
	// width, Y the height. The relay brings it within the bounds below and paces it; a session that
	// cannot resize ignores it.
	InputResize InputType = 4
	// InputClipboard is a text the operator pastes on the target (ADR-0096 §6). Unlike the other
	// inputs it is not 16 bytes: version, type, two reserved zero bytes, the text's length in
	// bytes (uint32), then the text in UTF-8, bounded as a CLIPBOARD message's. A client sends it
	// only when the HELLO says pasting is allowed, and only on the operator's explicit action.
	InputClipboard InputType = 5
	// InputPaste is an operator's password, encrypted for the proxy (ADR-0133): version, type, two
	// reserved zero bytes, the one-use paste token (32), the client's ephemeral P-256 public key
	// (65, uncompressed), the AES-GCM nonce (12), the ciphertext's length (uint16), then the
	// ciphertext: at most 512 bytes of text and the 16 of the tag. A client sends it only when the
	// HELLO carries the proxy's key, and only on the operator's explicit action.
	InputPaste InputType = 6
)

// Sizes of an InputPaste message (ADR-0133).
const (
	PasteTokenSize     = 32
	PasteNonceSize     = 12
	PasteInputHeader   = 4 + PasteTokenSize + PasteKeySize + PasteNonceSize + 2
	MaxPasteCiphertext = 512 + 16
	MaxPasteInputBytes = PasteInputHeader + MaxPasteCiphertext
	minPasteCiphertext = 1 + 16
)

// PasteInput is a decoded InputPaste message. Nothing in it is the text: it is only decrypted by the
// proxy, with the session's key.
type PasteInput struct {
	Token      [PasteTokenSize]byte
	ClientKey  [PasteKeySize]byte
	Nonce      [PasteNonceSize]byte
	Ciphertext []byte
}

// IsPasteInput says data is an InputPaste message, to be read with DecodePasteInput.
func IsPasteInput(data []byte) bool {
	return len(data) >= 2 && InputType(data[1]) == InputPaste
}

// EncodePasteInput writes the InputPaste message that DecodePasteInput reads back.
func EncodePasteInput(in PasteInput) ([]byte, error) {
	if len(in.Ciphertext) < minPasteCiphertext || len(in.Ciphertext) > MaxPasteCiphertext || in.ClientKey[0] != 0x04 {
		return nil, ErrOutOfBounds
	}
	out := make([]byte, PasteInputHeader+len(in.Ciphertext))
	out[0], out[1] = Version, byte(InputPaste)
	at := 4
	at += copy(out[at:], in.Token[:])
	at += copy(out[at:], in.ClientKey[:])
	at += copy(out[at:], in.Nonce[:])
	binary.BigEndian.PutUint16(out[at:], uint16(len(in.Ciphertext)))
	copy(out[at+2:], in.Ciphertext)
	return out, nil
}

// DecodePasteInput reads an InputPaste message strictly: its header, an uncompressed point, and a
// ciphertext whose length is exactly what follows and within the bounds.
func DecodePasteInput(data []byte) (PasteInput, error) {
	var in PasteInput
	if len(data) < PasteInputHeader+minPasteCiphertext || len(data) > MaxPasteInputBytes ||
		data[0] != Version || InputType(data[1]) != InputPaste || data[2] != 0 || data[3] != 0 {
		return in, ErrMalformedMessage
	}
	at := 4
	at += copy(in.Token[:], data[at:])
	at += copy(in.ClientKey[:], data[at:])
	at += copy(in.Nonce[:], data[at:])
	n := int(binary.BigEndian.Uint16(data[at:]))
	if in.ClientKey[0] != 0x04 || n < minPasteCiphertext || n > MaxPasteCiphertext || n != len(data)-PasteInputHeader {
		return PasteInput{}, ErrMalformedMessage
	}
	in.Ciphertext = append([]byte(nil), data[PasteInputHeader:]...)
	return in, nil
}

// ClipboardInputHeader is the fixed part of an InputClipboard message.
const ClipboardInputHeader = 8

// MaxClipboardInputBytes bounds an InputClipboard message: a UTF-16 unit is at most three bytes
// of UTF-8 (a pair of them, four), so a text within MaxClipboardTextUnits fits.
const MaxClipboardInputBytes = ClipboardInputHeader + 3*MaxClipboardTextUnits

// IsClipboardInput says data is an InputClipboard message, to be read with DecodeClipboardInput
// rather than DecodeInput.
func IsClipboardInput(data []byte) bool {
	return len(data) >= 2 && InputType(data[1]) == InputClipboard
}

// EncodeClipboardInput writes the InputClipboard message of text, which DecodeClipboardInput reads
// back: what the Admin UI and any other client of the screen contract send.
func EncodeClipboardInput(text string) ([]byte, error) {
	if err := validClipboardText(text); err != nil {
		return nil, err
	}
	out := make([]byte, ClipboardInputHeader+len(text))
	out[0], out[1] = Version, byte(InputClipboard)
	binary.BigEndian.PutUint32(out[4:8], uint32(len(text)))
	copy(out[ClipboardInputHeader:], text)
	return out, nil
}

// DecodeClipboardInput reads an InputClipboard message strictly: its header, a length that is
// exactly what follows, and a text the contract carries.
func DecodeClipboardInput(data []byte) (string, error) {
	if len(data) < ClipboardInputHeader || len(data) > MaxClipboardInputBytes ||
		data[0] != Version || InputType(data[1]) != InputClipboard || data[2] != 0 || data[3] != 0 ||
		uint64(binary.BigEndian.Uint32(data[4:8])) != uint64(len(data)-ClipboardInputHeader) {
		return "", ErrMalformedMessage
	}
	text := string(data[ClipboardInputHeader:])
	if err := validClipboardText(text); err != nil {
		return "", err
	}
	return text, nil
}

// validClipboardText is the bound of a clipboard text, both ways (ADR-0096 §3): valid UTF-8,
// without NUL, within MaxClipboardTextUnits UTF-16 units.
func validClipboardText(text string) error {
	if !utf8.ValidString(text) || strings.IndexByte(text, 0) >= 0 {
		return fmt.Errorf("%w: clipboard text not valid UTF-8 without NUL", ErrMalformedMessage)
	}
	units := 0
	for _, r := range text {
		units++
		if r >= 0x10000 {
			units++ // a surrogate pair
		}
		if units > MaxClipboardTextUnits {
			return fmt.Errorf("%w: clipboard text past %d UTF-16 units", ErrOutOfBounds, MaxClipboardTextUnits)
		}
	}
	return nil
}

// The bounds of a resize (ADR-0095 §4): past 2560 x 1600, a key frame risks the 4 MiB of a
// segment (ADR-0070). The width is even (MS-RDPEDISP).
const (
	MinResizeWidth  = 640
	MinResizeHeight = 480
	MaxResizeWidth  = 2560
	MaxResizeHeight = 1600
)

// ClampResize brings a size within the bounds of a resize, its width even: a size asked beyond
// them is not refused, the operator sees a desktop smaller or larger than the window (ADR-0095 §4).
func ClampResize(width, height uint16) (uint16, uint16) {
	width = min(max(width, MinResizeWidth), MaxResizeWidth) &^ 1
	height = min(max(height, MinResizeHeight), MaxResizeHeight)
	return width, height
}

const (
	KeyPressed            byte = 1
	KeyReleased           byte = 0
	AllowedPointerButtons byte = 0x1f
)

type InputEvent struct {
	Type     InputType
	Flags    byte
	Keysym   uint32
	Scancode uint16
	X        uint16
	Y        uint16
	Buttons  byte
	Wheel    int8
}

// DecodeInput validates the fixed 16-byte client-to-server event. Geometry is
// checked against the current framebuffer; key-table validation is performed
// by the protocol adapter before any event reaches the target.
func DecodeInput(data []byte, width, height uint32) (InputEvent, error) {
	var e InputEvent
	if len(data) > MaxInputBytes || len(data) != InputMessageSize {
		return e, ErrMalformedMessage
	}
	e.Type = InputType(data[1])
	e.Flags = data[2]
	if data[0] != Version || data[3] != 0 {
		return InputEvent{}, ErrMalformedMessage
	}
	e.Keysym = binary.BigEndian.Uint32(data[4:8])
	e.Scancode = binary.BigEndian.Uint16(data[8:10])
	e.X = binary.BigEndian.Uint16(data[10:12])
	e.Y = binary.BigEndian.Uint16(data[12:14])
	e.Buttons = data[14]
	e.Wheel = int8(data[15])
	switch e.Type {
	case InputKey:
		if e.Flags != KeyPressed && e.Flags != KeyReleased {
			return InputEvent{}, ErrMalformedMessage
		}
		if e.Keysym == 0 && e.Scancode == 0 {
			return InputEvent{}, ErrMalformedMessage
		}
		if e.X != 0 || e.Y != 0 || e.Buttons != 0 || e.Wheel != 0 {
			return InputEvent{}, ErrMalformedMessage
		}
	case InputPointer:
		if e.Flags != 0 || e.Keysym != 0 || e.Scancode != 0 ||
			uint32(e.X) >= width || uint32(e.Y) >= height ||
			e.Buttons & ^AllowedPointerButtons != 0 {
			return InputEvent{}, ErrOutOfBounds
		}
	case InputReleaseAll:
		if e.Flags != 0 || e.Keysym != 0 || e.Scancode != 0 ||
			e.X != 0 || e.Y != 0 || e.Buttons != 0 || e.Wheel != 0 {
			return InputEvent{}, ErrMalformedMessage
		}
	case InputResize:
		// A size, not a point of the frame: not checked against it.
		if e.Flags != 0 || e.Keysym != 0 || e.Scancode != 0 ||
			e.X == 0 || e.Y == 0 || e.Buttons != 0 || e.Wheel != 0 {
			return InputEvent{}, ErrMalformedMessage
		}
	default:
		return InputEvent{}, ErrUnsupported
	}
	return e, nil
}

func EncodeInput(e InputEvent) ([]byte, error) {
	out := make([]byte, InputMessageSize)
	out[0], out[1], out[2] = Version, byte(e.Type), e.Flags
	binary.BigEndian.PutUint32(out[4:8], e.Keysym)
	binary.BigEndian.PutUint16(out[8:10], e.Scancode)
	binary.BigEndian.PutUint16(out[10:12], e.X)
	binary.BigEndian.PutUint16(out[12:14], e.Y)
	out[14] = e.Buttons
	out[15] = byte(e.Wheel)
	decoded, err := DecodeInput(out, uint32(e.X)+1, uint32(e.Y)+1)
	if err != nil {
		return nil, err
	}
	if decoded.Type != e.Type {
		return nil, errors.New("screenstream: invalid input event")
	}
	return out, nil
}

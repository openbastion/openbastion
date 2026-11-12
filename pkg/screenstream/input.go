package screenstream

import (
	"encoding/binary"
	"errors"
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
)

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

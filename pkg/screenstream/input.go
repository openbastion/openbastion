package screenstream

import (
	"encoding/binary"
	"errors"
)

type InputType byte

const (
	InputKey InputType = 1
	InputPointer InputType = 2
	InputReleaseAll InputType = 3
)

const (
	KeyPressed byte = 1
	KeyReleased byte = 0
	AllowedPointerButtons byte = 0x1f
)

type InputEvent struct {
	Type InputType
	Flags byte
	Keysym uint32
	Scancode uint16
	X uint16
	Y uint16
	Buttons byte
	Wheel int8
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
		if e.X != 0 || e.Y != 0 || e.Buttons != 0 {
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
			e.X != 0 || e.Y != 0 || e.Buttons != 0 {
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

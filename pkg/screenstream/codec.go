// Package screenstream implements the versioned, bounded binary contract shared
// by the graphical proxy, API Gateway, and Admin UI (ADR-0071).
package screenstream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"time"
	"unicode/utf8"
)

const (
	Version           byte = 1
	HeaderSize             = 32
	MaxPNGBytes            = 4 << 20
	MaxPixels              = 16_777_216
	MaxInputBytes          = 64
	InputMessageSize       = 16
	MaxEndTextBytes        = 200
	MaxSessionIDBytes      = 1024
)

type MessageType byte

const (
	TypeFrame MessageType = 1
	TypeHello MessageType = 2
	TypeEnd   MessageType = 3
	// TypeFrameDelta is a partial frame (ADR-0092): the rectangles that changed since the frame of
	// the previous sequence, each a PNG. A FRAME is the key frame it builds on.
	TypeFrameDelta MessageType = 4
	// TypeClipboard is a text that crossed the clipboard (ADR-0096), in the session's sequence: it
	// is recorded, and acknowledged, like a frame, before it is delivered.
	TypeClipboard MessageType = 5
)

// ClipboardDirection is the way a clipboard text went (ADR-0096 §1).
type ClipboardDirection byte

const (
	ClipboardToTarget   ClipboardDirection = 1 // pasted by the operator on the target
	ClipboardFromTarget ClipboardDirection = 2 // copied from the target by the operator
)

// MaxClipboardTextUnits bounds a clipboard text in UTF-16 code units, the target's encoding: the
// 65 526 bytes of pkg/rdp (ADR-0096 §3), so that every text the channel carries can be recorded.
const MaxClipboardTextUnits = 32763

// clipboardHeader is the direction, then three reserved zero bytes.
const clipboardHeader = 4

// MaxDeltaRects bounds the rectangles of one partial frame (ADR-0092 §2).
const MaxDeltaRects = 64

// deltaRectHeader is x, y, width, height and the PNG's length, each a uint32.
const deltaRectHeader = 20

// Stable END codes are part of the v1 screen-stream wire contract (ADR-0071).
const (
	EndCodeSessionEnded uint16 = iota
	EndCodeSessionRevoked
	EndCodeSessionExpired
	EndCodeRecordingUnavailable
	EndCodeInputInvalid
	EndCodeTargetUnreachable
	EndCodePinMissing
	EndCodePinMismatch
	EndCodeTLSRequired
	EndCodeNLARequired
	EndCodeProtocolVersionUnsupported
	EndCodeCodecUnsupported
	EndCodeRecordingLost
	EndCodeTicketInvalid
)

type Protocol byte

const (
	ProtocolRDP Protocol = 1
	ProtocolVNC Protocol = 2
)

var (
	ErrMalformedMessage = errors.New("screenstream: malformed message")
	ErrUnsupported      = errors.New("screenstream: unsupported message")
	ErrOutOfBounds      = errors.New("screenstream: value outside allowed bounds")
	// ErrFrameTooLarge is a screen whose PNG is past MaxPNGBytes: it cannot be recorded, and a
	// session that cannot be recorded ends as a recording loss (ADR-0070, ADR-0071 §8), never
	// with the frame truncated or skipped.
	ErrFrameTooLarge = errors.New("screenstream: frame beyond the recordable size")
)

type Message struct {
	Type      MessageType
	Sequence  uint64
	Timestamp time.Time
	Width     uint32
	Height    uint32
	PNG       []byte

	// FRAME_DELTA-only: the changed rectangles, in the frame of Width x Height.
	Rects []Rect

	// HELLO-only fields.
	Protocol  Protocol
	ExpiresAt time.Time
	SessionID string
	// PointerDrawn says the frames carry the target's pointer (ADR-0091): the client hides its own.
	// Bit 0 of the HELLO's flags byte; the other bits are reserved and zero.
	PointerDrawn bool
	// Resizable says the session follows InputResize (ADR-0095 §6): bit 1 of the flags byte.
	Resizable bool
	// ClipboardToTarget says the session takes InputClipboard, ClipboardFromTarget that it sends
	// the texts copied on the target (ADR-0096 §6): bits 2 and 3. A client offers only what they say.
	ClipboardToTarget, ClipboardFromTarget bool

	// END-only fields. Text is a stable public message, never an internal error.
	EndCode uint16
	Text    string

	// CLIPBOARD-only fields: the way the text went, and the text, whole.
	Direction     ClipboardDirection
	ClipboardText string
}

// Rect is one changed rectangle of a partial frame: where it goes, and its pixels as a PNG of
// exactly Width x Height.
type Rect struct {
	X, Y, Width, Height uint32
	PNG                 []byte
}

// HelloPointerDrawn is the HELLO flag saying the frames carry the pointer (ADR-0091). It was a
// reserved zero byte: a HELLO without it is what it always was.
const HelloPointerDrawn = byte(0x01)

// HelloResizable is the HELLO flag saying the session follows InputResize (ADR-0095 §6): the client
// may send the size of its window. A HELLO without it is what it always was.
const HelloResizable = byte(0x02)

// HelloClipboardToTarget and HelloClipboardFromTarget are the HELLO flags of the clipboard's two
// directions (ADR-0096 §6). A HELLO without them is what it always was.
const (
	HelloClipboardToTarget   = byte(0x04)
	HelloClipboardFromTarget = byte(0x08)
)

// helloFlags are the HELLO flags this version knows; the others are reserved and zero.
const helloFlags = HelloPointerDrawn | HelloResizable | HelloClipboardToTarget | HelloClipboardFromTarget

// Encode serializes one v1 server-to-client message. It copies the payload into
// the returned buffer; callers may safely reuse their input slices afterwards.
func Encode(m Message) ([]byte, error) {
	switch m.Type {
	case TypeFrame:
		if err := validateFrame(m); err != nil {
			return nil, err
		}
		out := make([]byte, HeaderSize+len(m.PNG))
		putHeader(out, m)
		copy(out[HeaderSize:], m.PNG)
		return out, nil
	case TypeFrameDelta:
		size, err := validateDelta(m)
		if err != nil {
			return nil, err
		}
		out := make([]byte, HeaderSize+size)
		putHeader(out, m)
		p := out[HeaderSize:]
		binary.BigEndian.PutUint16(p, uint16(len(m.Rects)))
		at := 2
		for _, r := range m.Rects {
			binary.BigEndian.PutUint32(p[at:], r.X)
			binary.BigEndian.PutUint32(p[at+4:], r.Y)
			binary.BigEndian.PutUint32(p[at+8:], r.Width)
			binary.BigEndian.PutUint32(p[at+12:], r.Height)
			binary.BigEndian.PutUint32(p[at+16:], uint32(len(r.PNG)))
			copy(p[at+deltaRectHeader:], r.PNG)
			at += deltaRectHeader + len(r.PNG)
		}
		return out, nil
	case TypeHello:
		if m.Sequence != 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 ||
			(m.Protocol != ProtocolRDP && m.Protocol != ProtocolVNC) ||
			m.SessionID == "" || len(m.SessionID) > MaxSessionIDBytes ||
			!utf8.ValidString(m.SessionID) || m.ExpiresAt.IsZero() {
			return nil, ErrMalformedMessage
		}
		extra := 14 + len(m.SessionID)
		out := make([]byte, HeaderSize+extra)
		putHeader(out, m)
		out[HeaderSize] = byte(m.Protocol)
		if m.PointerDrawn {
			out[HeaderSize+1] |= HelloPointerDrawn
		}
		if m.Resizable {
			out[HeaderSize+1] |= HelloResizable
		}
		if m.ClipboardToTarget {
			out[HeaderSize+1] |= HelloClipboardToTarget
		}
		if m.ClipboardFromTarget {
			out[HeaderSize+1] |= HelloClipboardFromTarget
		}
		binary.BigEndian.PutUint64(out[HeaderSize+2:], uint64(m.ExpiresAt.Unix()))
		binary.BigEndian.PutUint32(out[HeaderSize+10:], uint32(len(m.SessionID)))
		copy(out[HeaderSize+14:], m.SessionID)
		return out, nil
	case TypeEnd:
		if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 || len(m.Text) > MaxEndTextBytes || !utf8.ValidString(m.Text) {
			return nil, ErrOutOfBounds
		}
		out := make([]byte, HeaderSize+4+len(m.Text))
		putHeader(out, m)
		binary.BigEndian.PutUint16(out[HeaderSize:], m.EndCode)
		binary.BigEndian.PutUint16(out[HeaderSize+2:], uint16(len(m.Text)))
		copy(out[HeaderSize+4:], m.Text)
		return out, nil
	case TypeClipboard:
		if err := validateClipboard(m); err != nil {
			return nil, err
		}
		out := make([]byte, HeaderSize+clipboardHeader+len(m.ClipboardText))
		putHeader(out, m)
		out[HeaderSize] = byte(m.Direction)
		copy(out[HeaderSize+clipboardHeader:], m.ClipboardText)
		return out, nil
	default:
		return nil, ErrUnsupported
	}
}

// validateClipboard checks a clipboard text against ADR-0096: a sequence and a time as a frame's,
// no screen size, one of the two directions, and a text of valid UTF-8, without NUL (the target's
// terminator), within MaxClipboardTextUnits. An empty text is a text: the target may copy nothing.
func validateClipboard(m Message) error {
	if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 ||
		(m.Direction != ClipboardToTarget && m.Direction != ClipboardFromTarget) {
		return ErrMalformedMessage
	}
	return validClipboardText(m.ClipboardText)
}

// Decode parses one complete v1 server-to-client message and rejects trailing,
// truncated, oversized, or non-canonical fields rather than guessing.
func Decode(data []byte) (Message, error) {
	var m Message
	if len(data) < HeaderSize || data[0] != Version || data[2] != 0 || data[3] != 0 {
		return m, ErrMalformedMessage
	}
	m.Type = MessageType(data[1])
	m.Sequence = binary.BigEndian.Uint64(data[4:12])
	m.Timestamp = time.Unix(0, int64(binary.BigEndian.Uint64(data[12:20]))).UTC()
	m.Width = binary.BigEndian.Uint32(data[20:24])
	m.Height = binary.BigEndian.Uint32(data[24:28])
	payloadLen := binary.BigEndian.Uint32(data[28:32])
	if uint64(payloadLen) > uint64(len(data)-HeaderSize) || int(payloadLen) != len(data)-HeaderSize {
		return Message{}, ErrMalformedMessage
	}
	switch m.Type {
	case TypeFrame:
		m.PNG = append([]byte(nil), data[HeaderSize:]...)
		if err := validateFrame(m); err != nil {
			return Message{}, err
		}
	case TypeFrameDelta:
		rects, err := decodeDeltaRects(data[HeaderSize:])
		if err != nil {
			return Message{}, err
		}
		m.Rects = rects
		if _, err := validateDelta(m); err != nil {
			return Message{}, err
		}
	case TypeHello:
		if m.Sequence != 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 || payloadLen < 14 {
			return Message{}, ErrMalformedMessage
		}
		p := data[HeaderSize:]
		m.Protocol = Protocol(p[0])
		if p[1]&^helloFlags != 0 {
			return Message{}, ErrMalformedMessage
		}
		m.PointerDrawn = p[1]&HelloPointerDrawn != 0
		m.Resizable = p[1]&HelloResizable != 0
		m.ClipboardToTarget = p[1]&HelloClipboardToTarget != 0
		m.ClipboardFromTarget = p[1]&HelloClipboardFromTarget != 0
		expires := binary.BigEndian.Uint64(p[2:10])
		if expires > math.MaxInt64 {
			return Message{}, ErrOutOfBounds
		}
		m.ExpiresAt = time.Unix(int64(expires), 0).UTC()
		idLen := binary.BigEndian.Uint32(p[10:14])
		if idLen == 0 || idLen > MaxSessionIDBytes || int(idLen) != len(p)-14 {
			return Message{}, ErrMalformedMessage
		}
		m.SessionID = string(p[14:])
		if !utf8.ValidString(m.SessionID) || (m.Protocol != ProtocolRDP && m.Protocol != ProtocolVNC) {
			return Message{}, ErrMalformedMessage
		}
	case TypeEnd:
		if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 || payloadLen < 4 {
			return Message{}, ErrMalformedMessage
		}
		p := data[HeaderSize:]
		textLen := binary.BigEndian.Uint16(p[2:4])
		if textLen > MaxEndTextBytes || int(textLen) != len(p)-4 || !utf8.Valid(p[4:]) {
			return Message{}, ErrMalformedMessage
		}
		m.EndCode = binary.BigEndian.Uint16(p[0:2])
		m.Text = string(p[4:])
	case TypeClipboard:
		p := data[HeaderSize:]
		if len(p) < clipboardHeader || p[1] != 0 || p[2] != 0 || p[3] != 0 {
			return Message{}, ErrMalformedMessage
		}
		m.Direction = ClipboardDirection(p[0])
		m.ClipboardText = string(p[clipboardHeader:])
		if err := validateClipboard(m); err != nil {
			return Message{}, err
		}
	default:
		return Message{}, ErrUnsupported
	}
	return m, nil
}

func putHeader(out []byte, m Message) {
	out[0] = Version
	out[1] = byte(m.Type)
	// Flags at bytes 2-3 are reserved and must remain zero.
	binary.BigEndian.PutUint64(out[4:12], m.Sequence)
	binary.BigEndian.PutUint64(out[12:20], uint64(m.Timestamp.UnixNano()))
	binary.BigEndian.PutUint32(out[20:24], m.Width)
	binary.BigEndian.PutUint32(out[24:28], m.Height)
	switch m.Type {
	case TypeFrame:
		binary.BigEndian.PutUint32(out[28:32], uint32(len(m.PNG)))
	case TypeFrameDelta:
		binary.BigEndian.PutUint32(out[28:32], uint32(len(out)-HeaderSize))
	case TypeHello:
		binary.BigEndian.PutUint32(out[28:32], uint32(14+len(m.SessionID)))
	case TypeEnd:
		binary.BigEndian.PutUint32(out[28:32], uint32(4+len(m.Text)))
	case TypeClipboard:
		binary.BigEndian.PutUint32(out[28:32], uint32(clipboardHeader+len(m.ClipboardText)))
	}
}

// validateDelta checks a partial frame against ADR-0092 §2 and returns its payload's size: a
// sequence and a frame size as a FRAME's, 1 to MaxDeltaRects rectangles, each non-empty, inside the
// frame and carrying a PNG, and the whole within MaxPNGBytes, the bound of what can be recorded.
func validateDelta(m Message) (int, error) {
	if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width == 0 || m.Height == 0 {
		return 0, ErrMalformedMessage
	}
	pixels := uint64(m.Width) * uint64(m.Height)
	if pixels > MaxPixels || len(m.Rects) == 0 || len(m.Rects) > MaxDeltaRects || m.PNG != nil {
		return 0, ErrOutOfBounds
	}
	size := 2
	for _, r := range m.Rects {
		if r.Width == 0 || r.Height == 0 || uint64(r.X)+uint64(r.Width) > uint64(m.Width) ||
			uint64(r.Y)+uint64(r.Height) > uint64(m.Height) || len(r.PNG) == 0 {
			return 0, ErrOutOfBounds
		}
		if len(r.PNG) < 8 || string(r.PNG[:8]) != "\x89PNG\r\n\x1a\n" {
			return 0, fmt.Errorf("%w: invalid PNG signature", ErrMalformedMessage)
		}
		size += deltaRectHeader + len(r.PNG)
		if size > MaxPNGBytes {
			return 0, fmt.Errorf("%w: %w", ErrOutOfBounds, ErrFrameTooLarge)
		}
	}
	return size, nil
}

// decodeDeltaRects reads a partial frame's payload: the count, then each rectangle's header and
// PNG. Nothing may be left over, and no length may run past the payload.
func decodeDeltaRects(p []byte) ([]Rect, error) {
	if len(p) < 2 {
		return nil, ErrMalformedMessage
	}
	count := int(binary.BigEndian.Uint16(p))
	if count == 0 || count > MaxDeltaRects {
		return nil, ErrOutOfBounds
	}
	rects := make([]Rect, 0, count)
	at := 2
	for i := 0; i < count; i++ {
		if len(p)-at < deltaRectHeader {
			return nil, ErrMalformedMessage
		}
		r := Rect{
			X: binary.BigEndian.Uint32(p[at:]), Y: binary.BigEndian.Uint32(p[at+4:]),
			Width: binary.BigEndian.Uint32(p[at+8:]), Height: binary.BigEndian.Uint32(p[at+12:]),
		}
		n := binary.BigEndian.Uint32(p[at+16:])
		at += deltaRectHeader
		if uint64(n) > uint64(len(p)-at) {
			return nil, ErrMalformedMessage
		}
		r.PNG = append([]byte(nil), p[at:at+int(n)]...)
		at += int(n)
		rects = append(rects, r)
	}
	if at != len(p) {
		return nil, ErrMalformedMessage
	}
	return rects, nil
}

func validateFrame(m Message) error {
	if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width == 0 || m.Height == 0 || m.Rects != nil {
		return ErrMalformedMessage
	}
	pixels := uint64(m.Width) * uint64(m.Height)
	if pixels > MaxPixels || pixels > math.MaxUint32 || len(m.PNG) == 0 || len(m.PNG) > MaxPNGBytes {
		return ErrOutOfBounds
	}
	// Verify PNG signature; full decoding belongs to the renderer/codec boundary.
	if len(m.PNG) < 8 || string(m.PNG[:8]) != "\x89PNG\r\n\x1a\n" {
		return fmt.Errorf("%w: invalid PNG signature", ErrMalformedMessage)
	}
	return nil
}

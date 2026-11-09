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
)

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

	// HELLO-only fields.
	Protocol  Protocol
	ExpiresAt time.Time
	SessionID string

	// END-only fields. Text is a stable public message, never an internal error.
	EndCode uint16
	Text    string
}

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
		// HeaderSize+1 is reserved and remains zero.
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
	default:
		return nil, ErrUnsupported
	}
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
	case TypeHello:
		if m.Sequence != 0 || m.Timestamp.IsZero() || m.Width != 0 || m.Height != 0 || payloadLen < 14 {
			return Message{}, ErrMalformedMessage
		}
		p := data[HeaderSize:]
		m.Protocol = Protocol(p[0])
		if p[1] != 0 {
			return Message{}, ErrMalformedMessage
		}
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
	case TypeHello:
		binary.BigEndian.PutUint32(out[28:32], uint32(14+len(m.SessionID)))
	case TypeEnd:
		binary.BigEndian.PutUint32(out[28:32], uint32(4+len(m.Text)))
	}
}

func validateFrame(m Message) error {
	if m.Sequence == 0 || m.Timestamp.IsZero() || m.Width == 0 || m.Height == 0 {
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

// Package pgwire implements the bounded framing needed by the PostgreSQL v3
// proxy. It deliberately does not expose an opaque TCP/TLS tunnel.
package pgwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"
)

const (
	ProtocolVersion3  uint32 = 196608
	SSLRequestCode    uint32 = 80877103
	GSSENCRequestCode uint32 = 80877104
	CancelRequestCode uint32 = 80877102

	// Startup packets are small metadata messages. A 64 KiB ceiling is well
	// above legitimate startup parameters while preventing allocation abuse.
	MaxStartupPacketBytes uint32 = 64 << 10
	// PostgreSQL messages can carry larger COPY frames, but this first
	// implementation keeps every frame finite at 16 MiB.
	MaxFrontendMessageBytes uint32 = 16 << 20
	MaxBackendMessageBytes  uint32 = 16 << 20
)

var (
	ErrPacketTooLarge      = errors.New("postgresql packet exceeds the configured limit")
	ErrMalformedPacket     = errors.New("malformed postgresql packet")
	ErrUnsupportedProtocol = errors.New("unsupported postgresql protocol version")
)

type PacketKind uint8

const (
	Startup PacketKind = iota + 1
	SSLRequest
	GSSENCRequest
	CancelRequest
)

type StartupPacket struct {
	Kind            PacketKind
	ProtocolVersion uint32
	Parameters      map[string]string
	CancelPID       uint32
	CancelSecret    uint32
}

type FrontendMessage struct {
	Type    byte
	Payload []byte
}

// ReadStartupPacket reads one untyped PostgreSQL startup packet. It never
// allocates based on a peer-provided length until that length has been bounded.
func ReadStartupPacket(r io.Reader) (StartupPacket, error) {
	var header [4]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return StartupPacket{}, err
	}
	length := binary.BigEndian.Uint32(header[:])
	if length < 8 {
		return StartupPacket{}, fmt.Errorf("%w: startup length %d is below 8", ErrMalformedPacket, length)
	}
	if length > MaxStartupPacketBytes {
		return StartupPacket{}, ErrPacketTooLarge
	}
	body := make([]byte, int(length)-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return StartupPacket{}, fmt.Errorf("read startup body: %w", err)
	}
	code := binary.BigEndian.Uint32(body[:4])
	packet := StartupPacket{ProtocolVersion: code}
	switch code {
	case SSLRequestCode:
		if length != 8 {
			return StartupPacket{}, fmt.Errorf("%w: SSLRequest length must be 8", ErrMalformedPacket)
		}
		packet.Kind = SSLRequest
		return packet, nil
	case GSSENCRequestCode:
		if length != 8 {
			return StartupPacket{}, fmt.Errorf("%w: GSSENCRequest length must be 8", ErrMalformedPacket)
		}
		packet.Kind = GSSENCRequest
		return packet, nil
	case CancelRequestCode:
		if length != 16 {
			return StartupPacket{}, fmt.Errorf("%w: CancelRequest length must be 16", ErrMalformedPacket)
		}
		packet.Kind = CancelRequest
		packet.CancelPID = binary.BigEndian.Uint32(body[4:8])
		packet.CancelSecret = binary.BigEndian.Uint32(body[8:12])
		return packet, nil
	case ProtocolVersion3:
		packet.Kind = Startup
		params, err := parseStartupParameters(body[4:])
		if err != nil {
			return StartupPacket{}, err
		}
		packet.Parameters = params
		return packet, nil
	default:
		return StartupPacket{}, fmt.Errorf("%w: %d", ErrUnsupportedProtocol, code)
	}
}

func parseStartupParameters(payload []byte) (map[string]string, error) {
	params := make(map[string]string)
	for offset := 0; ; {
		key, next, ok := readCString(payload, offset)
		if !ok {
			return nil, fmt.Errorf("%w: startup parameter name is not terminated", ErrMalformedPacket)
		}
		if key == "" {
			if next != len(payload) {
				return nil, fmt.Errorf("%w: bytes follow startup parameter terminator", ErrMalformedPacket)
			}
			if len(params) == 0 {
				return nil, fmt.Errorf("%w: startup parameters are empty", ErrMalformedPacket)
			}
			return params, nil
		}
		if !utf8.ValidString(key) {
			return nil, fmt.Errorf("%w: startup parameter name is not UTF-8", ErrMalformedPacket)
		}
		value, afterValue, ok := readCString(payload, next)
		if !ok || !utf8.ValidString(value) {
			return nil, fmt.Errorf("%w: startup parameter value is not a terminated UTF-8 string", ErrMalformedPacket)
		}
		if _, exists := params[key]; exists {
			return nil, fmt.Errorf("%w: duplicate startup parameter", ErrMalformedPacket)
		}
		params[key] = value
		offset = afterValue
	}
}

func readCString(payload []byte, offset int) (string, int, bool) {
	if offset < 0 || offset >= len(payload) {
		return "", offset, false
	}
	for i := offset; i < len(payload); i++ {
		if payload[i] == 0 {
			return string(payload[offset:i]), i + 1, true
		}
	}
	return "", offset, false
}

// ReadFrontendMessage reads a typed frontend message (type byte, int32 length,
// payload). The length includes its own four bytes, but not the type byte.
func ReadFrontendMessage(r io.Reader) (FrontendMessage, error) {
	var header [5]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return FrontendMessage{}, err
	}
	length := binary.BigEndian.Uint32(header[1:])
	if length < 4 {
		return FrontendMessage{}, fmt.Errorf("%w: frontend message length %d is below 4", ErrMalformedPacket, length)
	}
	if length > MaxFrontendMessageBytes {
		return FrontendMessage{}, ErrPacketTooLarge
	}
	payload := make([]byte, int(length)-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return FrontendMessage{}, fmt.Errorf("read frontend message: %w", err)
	}
	return FrontendMessage{Type: header[0], Payload: payload}, nil
}

// WriteBackendMessage writes one typed backend message with a bounded payload.
func WriteBackendMessage(w io.Writer, kind byte, payload []byte) error {
	if uint64(len(payload))+4 > uint64(MaxBackendMessageBytes) {
		return ErrPacketTooLarge
	}
	var header [5]byte
	header[0] = kind
	binary.BigEndian.PutUint32(header[1:], uint32(len(payload)+4))
	if err := writeFull(w, header[:]); err != nil {
		return fmt.Errorf("write backend message header: %w", err)
	}
	if err := writeFull(w, payload); err != nil {
		return fmt.Errorf("write backend message payload: %w", err)
	}
	return nil
}

// WriteSSLResponse writes the one-byte response to PostgreSQL SSLRequest.
func WriteSSLResponse(w io.Writer, accepted bool) error {
	response := byte('N')
	if accepted {
		response = 'S'
	}
	return writeFull(w, []byte{response})
}

func writeFull(w io.Writer, p []byte) error {
	for len(p) > 0 {
		n, err := w.Write(p)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		p = p[n:]
	}
	return nil
}

package pgwire

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

const (
	AuthenticationOK                int32 = 0
	AuthenticationCleartextPassword int32 = 3
	AuthenticationSASL              int32 = 10
	AuthenticationSASLContinue      int32 = 11
	AuthenticationSASLFinal         int32 = 12
)

var ErrMalformedMessage = errors.New("malformed postgresql message")

// ParsePasswordMessage extracts the C-string form used by the frontend
// AuthenticationCleartextPassword exchange. SASL PasswordMessages are raw
// mechanism payloads and must not be passed to this helper.
func ParsePasswordMessage(message FrontendMessage) ([]byte, error) {
	if message.Type != 'p' || len(message.Payload) < 1 || message.Payload[len(message.Payload)-1] != 0 {
		return nil, ErrMalformedMessage
	}
	for _, b := range message.Payload[:len(message.Payload)-1] {
		if b == 0 {
			return nil, ErrMalformedMessage
		}
	}
	return append([]byte(nil), message.Payload[:len(message.Payload)-1]...), nil
}

func WriteAuthenticationRequest(w io.Writer, code int32, data []byte) error {
	payload := make([]byte, 4+len(data))
	binary.BigEndian.PutUint32(payload[:4], uint32(code))
	copy(payload[4:], data)
	return WriteBackendMessage(w, 'R', payload)
}

func WriteParameterStatus(w io.Writer, name, value string) error {
	if name == "" || strings.ContainsRune(name, 0) || strings.ContainsRune(value, 0) {
		return ErrMalformedMessage
	}
	payload := make([]byte, 0, len(name)+len(value)+2)
	payload = append(payload, name...)
	payload = append(payload, 0)
	payload = append(payload, value...)
	payload = append(payload, 0)
	return WriteBackendMessage(w, 'S', payload)
}

func WriteBackendKeyData(w io.Writer, processID, secretKey uint32) error {
	var payload [8]byte
	binary.BigEndian.PutUint32(payload[:4], processID)
	binary.BigEndian.PutUint32(payload[4:], secretKey)
	return WriteBackendMessage(w, 'K', payload[:])
}

func WriteReadyForQuery(w io.Writer, transactionStatus byte) error {
	if transactionStatus != 'I' && transactionStatus != 'T' && transactionStatus != 'E' {
		return fmt.Errorf("%w: invalid transaction status", ErrMalformedMessage)
	}
	return WriteBackendMessage(w, 'Z', []byte{transactionStatus})
}

func ParseCommandComplete(message FrontendMessage) (string, error) {
	if message.Type != 'C' || len(message.Payload) < 2 || message.Payload[len(message.Payload)-1] != 0 {
		return "", ErrMalformedMessage
	}
	for _, b := range message.Payload[:len(message.Payload)-1] {
		if b == 0 {
			return "", ErrMalformedMessage
		}
	}
	return string(message.Payload[:len(message.Payload)-1]), nil
}

// WriteErrorResponse emits a bounded PostgreSQL ErrorResponse. Callers must
// pass generic, non-secret messages; target diagnostics belong in protected logs.
func WriteErrorResponse(w io.Writer, severity, sqlState, message string) error {
	if severity == "" || len(severity) > 32 || len(sqlState) != 5 || len(message) == 0 || len(message) > 256 ||
		strings.ContainsRune(severity, 0) || strings.ContainsRune(sqlState, 0) || strings.ContainsRune(message, 0) {
		return ErrMalformedMessage
	}
	payload := make([]byte, 0, len(severity)+len(sqlState)+len(message)+6)
	payload = append(payload, 'S')
	payload = append(payload, severity...)
	payload = append(payload, 0, 'C')
	payload = append(payload, sqlState...)
	payload = append(payload, 0, 'M')
	payload = append(payload, message...)
	payload = append(payload, 0, 0)
	return WriteBackendMessage(w, 'E', payload)
}

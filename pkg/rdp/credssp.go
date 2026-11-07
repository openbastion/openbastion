package rdp

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	credSSPMinVersion = uint32(2)
	credSSPMaxVersion = uint32(6)
	maxCredSSPMessage = 64 << 10
	maxCredSSPToken   = 16 << 10
	maxCredSSPTokens  = 8
)

var ErrCredSSPMessage = errors.New("rdp: malformed or unsupported CredSSP TSRequest")

// TSRequest is the bounded ASN.1 structure used to frame CredSSP messages.
// Token bytes are opaque SPNEGO/NTLM messages; this type never creates or
// verifies credentials and is not an authentication implementation by itself.
type TSRequest struct {
	Version     uint32
	NegoTokens  [][]byte
	AuthInfo    []byte
	PubKeyAuth  []byte
	ErrorCode   *uint32
	ClientNonce []byte
}

// MarshalTSRequest encodes a strict DER CredSSP TSRequest (MS-CSSP). Optional
// fields are emitted in ascending tag order, and all payload sizes are bounded.
func MarshalTSRequest(req TSRequest) ([]byte, error) {
	if req.Version < credSSPMinVersion || req.Version > credSSPMaxVersion || len(req.NegoTokens) > maxCredSSPTokens || len(req.AuthInfo) > maxCredSSPToken || len(req.PubKeyAuth) > maxCredSSPToken || len(req.ClientNonce) > 32 {
		return nil, ErrCredSSPMessage
	}
	var body []byte
	version, err := derInteger(uint64(req.Version))
	if err != nil {
		return nil, err
	}
	body = append(body, derWrap(0xa0, version)...)
	if len(req.NegoTokens) > 0 {
		var tokens []byte
		for _, token := range req.NegoTokens {
			if len(token) == 0 || len(token) > maxCredSSPToken {
				return nil, ErrCredSSPMessage
			}
			item := derWrap(0x30, derWrap(0xa0, derWrap(0x04, token))) // NegoDataItem SEQUENCE
			tokens = append(tokens, item...)
		}
		body = append(body, derWrap(0xa1, derWrap(0x30, tokens))...)
	}
	if req.AuthInfo != nil {
		body = append(body, derWrap(0xa2, derWrap(0x04, req.AuthInfo))...)
	}
	if req.PubKeyAuth != nil {
		body = append(body, derWrap(0xa3, derWrap(0x04, req.PubKeyAuth))...)
	}
	if req.ErrorCode != nil {
		value, err := derInteger(uint64(*req.ErrorCode))
		if err != nil {
			return nil, err
		}
		body = append(body, derWrap(0xa4, value)...)
	}
	if req.ClientNonce != nil {
		if len(req.ClientNonce) != 32 {
			return nil, ErrCredSSPMessage
		}
		body = append(body, derWrap(0xa5, derWrap(0x04, req.ClientNonce))...)
	}
	encoded := derWrap(0x30, body)
	if len(encoded) > maxCredSSPMessage {
		return nil, ErrCredSSPMessage
	}
	return encoded, nil
}

// ParseTSRequest parses one complete, bounded DER TSRequest and rejects unknown
// fields, duplicate/out-of-order tags, indefinite lengths and non-canonical DER.
func ParseTSRequest(data []byte) (TSRequest, error) {
	var req TSRequest
	if len(data) == 0 || len(data) > maxCredSSPMessage {
		return req, ErrCredSSPMessage
	}
	outer, rest, err := derRead(data)
	if err != nil || outer.tag != 0x30 || len(rest) != 0 {
		return req, ErrCredSSPMessage
	}
	body := outer.value
	lastTag := byte(0x9f)
	seenVersion := false
	for len(body) > 0 {
		field, tail, err := derRead(body)
		if err != nil || field.tag < 0xa0 || field.tag > 0xa5 || field.tag <= lastTag {
			return TSRequest{}, ErrCredSSPMessage
		}
		lastTag, body = field.tag, tail
		switch field.tag {
		case 0xa0:
			value, rem, err := derRead(field.value)
			if err != nil || value.tag != 0x02 || len(rem) != 0 {
				return TSRequest{}, ErrCredSSPMessage
			}
			n, err := parseDERUint(value.value)
			if err != nil || n < uint64(credSSPMinVersion) || n > uint64(credSSPMaxVersion) {
				return TSRequest{}, ErrCredSSPMessage
			}
			req.Version, seenVersion = uint32(n), true
		case 0xa1:
			seq, rem, err := derRead(field.value)
			if err != nil || seq.tag != 0x30 || len(rem) != 0 {
				return TSRequest{}, ErrCredSSPMessage
			}
			for tokens := seq.value; len(tokens) > 0; {
				if len(req.NegoTokens) >= maxCredSSPTokens {
					return TSRequest{}, ErrCredSSPMessage
				}
				item, tail, err := derRead(tokens)
				if err != nil || item.tag != 0x30 {
					return TSRequest{}, ErrCredSSPMessage
				}
				tokens = tail
				negoToken, rem, err := derRead(item.value)
				if err != nil || negoToken.tag != 0xa0 || len(rem) != 0 {
					return TSRequest{}, ErrCredSSPMessage
				}
				token, rem, err := derRead(negoToken.value)
				if err != nil || token.tag != 0x04 || len(rem) != 0 || len(token.value) == 0 || len(token.value) > maxCredSSPToken {
					return TSRequest{}, ErrCredSSPMessage
				}
				req.NegoTokens = append(req.NegoTokens, append([]byte(nil), token.value...))
			}
		case 0xa2, 0xa3, 0xa5:
			value, rem, err := derRead(field.value)
			if err != nil || value.tag != 0x04 || len(rem) != 0 || len(value.value) > maxCredSSPToken {
				return TSRequest{}, ErrCredSSPMessage
			}
			payload := append([]byte(nil), value.value...)
			switch field.tag {
			case 0xa2:
				req.AuthInfo = payload
			case 0xa3:
				req.PubKeyAuth = payload
			case 0xa5:
				if len(payload) != 32 {
					return TSRequest{}, ErrCredSSPMessage
				}
				req.ClientNonce = payload
			}
		case 0xa4:
			value, rem, err := derRead(field.value)
			if err != nil || value.tag != 0x02 || len(rem) != 0 {
				return TSRequest{}, ErrCredSSPMessage
			}
			code, err := parseDERInt32(value.value)
			if err != nil {
				return TSRequest{}, ErrCredSSPMessage
			}
			req.ErrorCode = &code
		}
	}
	if !seenVersion {
		return TSRequest{}, fmt.Errorf("%w: missing version", ErrCredSSPMessage)
	}
	return req, nil
}

type derValue struct {
	tag   byte
	value []byte
}

func derRead(data []byte) (derValue, []byte, error) {
	if len(data) < 2 {
		return derValue{}, nil, ErrCredSSPMessage
	}
	tag, first := data[0], data[1]
	if tag&0x1f == 0x1f {
		return derValue{}, nil, ErrCredSSPMessage // high-tag-number form not used by TSRequest
	}
	header, length := 2, int(first)
	if first == 0x80 {
		return derValue{}, nil, ErrCredSSPMessage // indefinite length is BER, not DER
	}
	if first&0x80 != 0 {
		count := int(first & 0x7f)
		if count == 0 || count > 3 || len(data) < 2+count || data[2] == 0 {
			return derValue{}, nil, ErrCredSSPMessage
		}
		header += count
		length = 0
		for _, b := range data[2:header] {
			length = length<<8 | int(b)
		}
		if length < 128 || (count > 1 && length < 256) || (count > 2 && length < 65536) {
			return derValue{}, nil, ErrCredSSPMessage
		}
	}
	if length > maxCredSSPMessage || header+length > len(data) {
		return derValue{}, nil, ErrCredSSPMessage
	}
	return derValue{tag: tag, value: data[header : header+length]}, data[header+length:], nil
}

func derWrap(tag byte, value []byte) []byte {
	out := []byte{tag}
	switch length := len(value); {
	case length < 128:
		out = append(out, byte(length))
	case length <= 0xff:
		out = append(out, 0x81, byte(length))
	case length <= 0xffff:
		out = append(out, 0x82, byte(length>>8), byte(length))
	default:
		out = append(out, 0x83, byte(length>>16), byte(length>>8), byte(length))
	}
	return append(out, value...)
}

func derInteger(value uint64) ([]byte, error) {
	var raw [9]byte
	binary.BigEndian.PutUint64(raw[1:], value)
	start := 1
	for start < 8 && raw[start] == 0 {
		start++
	}
	if raw[start]&0x80 != 0 {
		start--
	}
	return derWrap(0x02, raw[start:]), nil
}

func parseDERUint(value []byte) (uint64, error) {
	if len(value) == 0 || len(value) > 9 || value[0]&0x80 != 0 || (len(value) > 1 && value[0] == 0 && value[1]&0x80 == 0) {
		return 0, ErrCredSSPMessage
	}
	if len(value) == 9 {
		if value[0] != 0 {
			return 0, ErrCredSSPMessage
		}
		value = value[1:]
	}
	var n uint64
	for _, b := range value {
		n = n<<8 | uint64(b)
	}
	return n, nil
}

// parseDERInt32 decodes the signed ASN.1 INTEGER used for CredSSP errorCode.
// NTSTATUS is a signed 32-bit value on the wire; converting it to uint32 keeps
// its conventional hexadecimal bit pattern for callers and diagnostics. Values
// in the positive uint32 range are also accepted for interoperability.
func parseDERInt32(value []byte) (uint32, error) {
	if len(value) == 0 || len(value) > 5 {
		return 0, ErrCredSSPMessage
	}
	if len(value) > 1 && ((value[0] == 0x00 && value[1]&0x80 == 0) || (value[0] == 0xff && value[1]&0x80 != 0)) {
		return 0, ErrCredSSPMessage
	}
	n := int64(0)
	if value[0]&0x80 != 0 {
		n = -1
	}
	for _, b := range value {
		n = (n << 8) | int64(b)
	}
	if n < -1<<31 || n > 1<<32-1 {
		return 0, ErrCredSSPMessage
	}
	return uint32(n), nil
}

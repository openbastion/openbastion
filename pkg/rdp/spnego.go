package rdp

import (
	"bytes"
	"encoding/asn1"
	"errors"
)

const (
	maxSPNEGOToken = maxCredSSPToken
	maxSPNEGOMechs = 8
)

var (
	ErrSPNEGOToken       = errors.New("invalid SPNEGO token")
	ErrSPNEGOMechanism   = errors.New("unsupported SPNEGO mechanism")
	ErrSPNEGONegotiation = errors.New("SPNEGO negotiation rejected")
)

var (
	spnegoOID = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 2}
	ntlmOID   = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 2, 2, 10}
)

// SPNEGONegTokenInit is a bounded, parsed SPNEGO initial negotiation token.
// MechanismToken and MechanismListMIC are opaque and must not be interpreted
// as authenticated until the corresponding SPNEGO/NTLM MIC checks exist.
type SPNEGONegTokenInit struct {
	Mechanisms       []asn1.ObjectIdentifier
	MechanismToken   []byte
	MechanismListMIC []byte
}

// SPNEGONegTokenResp is a bounded, parsed SPNEGO response token.
type SPNEGONegTokenResp struct {
	State            uint64
	SupportedMech    asn1.ObjectIdentifier
	ResponseToken    []byte
	MechanismListMIC []byte
}

// ParseSPNEGONegTokenInit parses the RFC 4178 InitialContextToken form.
// This implementation deliberately permits only NTLM as the offered
// mechanism; it does not imply that NTLM authentication is implemented.
func ParseSPNEGONegTokenInit(data []byte) (SPNEGONegTokenInit, error) {
	var out SPNEGONegTokenInit
	if len(data) == 0 || len(data) > maxSPNEGOToken {
		return out, ErrSPNEGOToken
	}
	app, rest, err := derRead(data)
	if err != nil || app.tag != 0x60 || len(rest) != 0 {
		return out, ErrSPNEGOToken
	}
	oidValue, rest, err := derRead(app.value)
	if err != nil || oidValue.tag != 0x06 {
		return out, ErrSPNEGOToken
	}
	oid, err := parseOID(oidValue.value)
	if err != nil || !oid.Equal(spnegoOID) {
		return out, ErrSPNEGOToken
	}
	choice, rest, err := derRead(rest)
	if err != nil || choice.tag != 0xa0 || len(rest) != 0 {
		return out, ErrSPNEGOToken
	}
	seq, rest, err := derRead(choice.value)
	if err != nil || seq.tag != 0x30 || len(rest) != 0 {
		return out, ErrSPNEGOToken
	}
	fields, err := readOrderedFields(seq.value, 4)
	if err != nil {
		return out, err
	}
	if len(fields) == 0 || fields[0].tag != 0xa0 {
		return out, ErrSPNEGOToken
	}
	mechSeq, tail, err := derRead(fields[0].value)
	if err != nil || mechSeq.tag != 0x30 || len(tail) != 0 {
		return out, ErrSPNEGOToken
	}
	for rest := mechSeq.value; len(rest) > 0; {
		if len(out.Mechanisms) == maxSPNEGOMechs {
			return SPNEGONegTokenInit{}, ErrSPNEGOToken
		}
		item, next, e := derRead(rest)
		if e != nil || item.tag != 0x06 {
			return SPNEGONegTokenInit{}, ErrSPNEGOToken
		}
		mechanism, e := parseOID(item.value)
		if e != nil {
			return SPNEGONegTokenInit{}, ErrSPNEGOToken
		}
		if !mechanism.Equal(ntlmOID) {
			return SPNEGONegTokenInit{}, ErrSPNEGOMechanism
		}
		for _, prior := range out.Mechanisms {
			if prior.Equal(mechanism) {
				return SPNEGONegTokenInit{}, ErrSPNEGOToken
			}
		}
		out.Mechanisms = append(out.Mechanisms, mechanism)
		rest = next
	}
	if len(out.Mechanisms) == 0 {
		return SPNEGONegTokenInit{}, ErrSPNEGOToken
	}
	for _, field := range fields[1:] {
		switch field.tag {
		case 0xa1: // reqFlags BIT STRING
			bits, tail, e := derRead(field.value)
			if e != nil || bits.tag != 0x03 || len(tail) != 0 || len(bits.value) == 0 || bits.value[0] > 7 {
				return SPNEGONegTokenInit{}, ErrSPNEGOToken
			}
			unused := bits.value[0]
			if len(bits.value) == 1 && unused != 0 || len(bits.value) > 1 && unused > 0 && bits.value[len(bits.value)-1]&byte((1<<unused)-1) != 0 {
				return SPNEGONegTokenInit{}, ErrSPNEGOToken
			}
		case 0xa2:
			out.MechanismToken, err = readExplicitOctets(field.value)
			if err != nil {
				return SPNEGONegTokenInit{}, err
			}
		case 0xa3:
			out.MechanismListMIC, err = readExplicitOctets(field.value)
			if err != nil {
				return SPNEGONegTokenInit{}, err
			}
		default:
			return SPNEGONegTokenInit{}, ErrSPNEGOToken
		}
	}
	return out, nil
}

// ParseSPNEGONegTokenResp parses the RFC 4178 NegTokenResp choice.
func ParseSPNEGONegTokenResp(data []byte) (SPNEGONegTokenResp, error) {
	var out SPNEGONegTokenResp
	if len(data) == 0 || len(data) > maxSPNEGOToken {
		return out, ErrSPNEGOToken
	}
	choice, rest, err := derRead(data)
	if err != nil || choice.tag != 0xa1 || len(rest) != 0 {
		return out, ErrSPNEGOToken
	}
	seq, rest, err := derRead(choice.value)
	if err != nil || seq.tag != 0x30 || len(rest) != 0 {
		return out, ErrSPNEGOToken
	}
	fields, err := readOrderedFields(seq.value, 4)
	if err != nil {
		return out, err
	}
	for _, field := range fields {
		switch field.tag {
		case 0xa0: // negState ENUMERATED
			value, tail, e := derRead(field.value)
			if e != nil || value.tag != 0x0a || len(tail) != 0 {
				return SPNEGONegTokenResp{}, ErrSPNEGOToken
			}
			out.State, e = parseDERUint(value.value)
			if e != nil || out.State > 3 {
				return SPNEGONegTokenResp{}, ErrSPNEGOToken
			}
			if out.State == 2 || out.State == 3 {
				return SPNEGONegTokenResp{}, ErrSPNEGONegotiation
			}
		case 0xa1: // supportedMech OBJECT IDENTIFIER
			value, tail, e := derRead(field.value)
			if e != nil || value.tag != 0x06 || len(tail) != 0 {
				return SPNEGONegTokenResp{}, ErrSPNEGOToken
			}
			out.SupportedMech, e = parseOID(value.value)
			if e != nil {
				return SPNEGONegTokenResp{}, ErrSPNEGOToken
			}
			if !out.SupportedMech.Equal(ntlmOID) {
				return SPNEGONegTokenResp{}, ErrSPNEGOMechanism
			}
		case 0xa2:
			out.ResponseToken, err = readExplicitOctets(field.value)
			if err != nil {
				return SPNEGONegTokenResp{}, err
			}
		case 0xa3:
			out.MechanismListMIC, err = readExplicitOctets(field.value)
			if err != nil {
				return SPNEGONegTokenResp{}, err
			}
		default:
			return SPNEGONegTokenResp{}, ErrSPNEGOToken
		}
	}
	return out, nil
}

type derField struct {
	tag   byte
	value []byte
}

func readOrderedFields(data []byte, max int) ([]derField, error) {
	var fields []derField
	last := byte(0)
	for len(data) > 0 {
		if len(fields) == max {
			return nil, ErrSPNEGOToken
		}
		value, rest, err := derRead(data)
		if err != nil || value.tag < 0xa0 || value.tag > 0xa3 || value.tag <= last {
			return nil, ErrSPNEGOToken
		}
		fields = append(fields, derField{tag: value.tag, value: value.value})
		last, data = value.tag, rest
	}
	return fields, nil
}

func readExplicitOctets(data []byte) ([]byte, error) {
	value, rest, err := derRead(data)
	if err != nil || value.tag != 0x04 || len(rest) != 0 || len(value.value) > maxSPNEGOToken {
		return nil, ErrSPNEGOToken
	}
	return append([]byte(nil), value.value...), nil
}

func parseOID(data []byte) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	encoded := derWrap(0x06, data)
	rest, err := asn1.Unmarshal(encoded, &oid)
	if err != nil || len(rest) != 0 || len(oid) < 2 {
		return nil, ErrSPNEGOToken
	}
	canonical, err := asn1.Marshal(oid)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return nil, ErrSPNEGOToken
	}
	return oid, nil
}

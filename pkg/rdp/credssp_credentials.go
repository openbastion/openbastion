package rdp

import (
	"encoding/binary"
	"errors"
	"unicode/utf16"
	"unicode/utf8"
)

var ErrCredSSPCredentials = errors.New("rdp: invalid CredSSP password credentials")

const (
	maxCredSSPDomainBytes   = maxNTLMv2Identity
	maxCredSSPUsernameBytes = maxNTLMv2Identity
	maxCredSSPPasswordBytes = maxNTLMv2Password
)

// marshalCredSSPPasswordCredentials encodes TSCredentials(credType=1) wrapping
// TSPasswordCreds. MS-CSSP represents the three password fields as OCTET STRINGs
// containing UTF-16LE text; the resulting DER is then sealed by GSS_Wrap before
// it is placed in TSRequest.authInfo.
func marshalCredSSPPasswordCredentials(domain, username string, password []byte) ([]byte, error) {
	if len(domain) > maxCredSSPDomainBytes || len(username) == 0 || len(username) > maxCredSSPUsernameBytes ||
		len(password) == 0 || len(password) > maxCredSSPPasswordBytes ||
		!validNTLMv2Identity(domain) || !validNTLMv2Identity(username) || !utf8.Valid(password) {
		return nil, ErrCredSSPCredentials
	}

	domainRunes := []rune(domain)
	domainUTF16 := encodeUTF16LE(domainRunes)
	clearRunes(domainRunes)
	usernameRunes := []rune(username)
	usernameUTF16 := encodeUTF16LE(usernameRunes)
	clearRunes(usernameRunes)
	passwordUTF16, err := encodeUTF8BytesAsUTF16LE(password)
	if err != nil {
		clear(domainUTF16)
		clear(usernameUTF16)
		return nil, ErrCredSSPCredentials
	}
	defer clear(domainUTF16)
	defer clear(usernameUTF16)
	defer clear(passwordUTF16)

	domainField := derExplicitOctetString(0xa0, domainUTF16)
	usernameField := derExplicitOctetString(0xa1, usernameUTF16)
	passwordField := derExplicitOctetString(0xa2, passwordUTF16)
	passwordFields := make([]byte, 0, len(domainField)+len(usernameField)+len(passwordField))
	passwordFields = append(passwordFields, domainField...)
	passwordFields = append(passwordFields, usernameField...)
	passwordFields = append(passwordFields, passwordField...)
	clear(domainField)
	clear(usernameField)
	clear(passwordField)
	tsPasswordCreds := derWrap(0x30, passwordFields)
	clear(passwordFields)
	defer clear(tsPasswordCreds)

	credTypeInteger := derWrap(0x02, []byte{1})
	credTypeField := derWrap(0xa0, credTypeInteger)
	clear(credTypeInteger)
	credentialsOctets := derWrap(0x04, tsPasswordCreds)
	credentialsField := derWrap(0xa1, credentialsOctets)
	clear(credentialsOctets)
	credentialsFields := make([]byte, 0, len(credTypeField)+len(credentialsField))
	credentialsFields = append(credentialsFields, credTypeField...)
	credentialsFields = append(credentialsFields, credentialsField...)
	clear(credTypeField)
	clear(credentialsField)
	encoded := derWrap(0x30, credentialsFields)
	clear(credentialsFields)
	if len(encoded) > maxCredSSPToken-ntlmSSPMessageSignatureSize {
		clear(encoded)
		return nil, ErrCredSSPCredentials
	}
	return encoded, nil
}

func encodeUTF16LE(value []rune) []byte {
	units := utf16.Encode(value)
	encoded := make([]byte, len(units)*2)
	for i, unit := range units {
		binary.LittleEndian.PutUint16(encoded[i*2:], unit)
	}
	clear(units)
	return encoded
}

func encodeUTF8BytesAsUTF16LE(value []byte) ([]byte, error) {
	if !utf8.Valid(value) {
		return nil, ErrCredSSPCredentials
	}
	runes := make([]rune, 0, len(value))
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		runes = append(runes, r)
		value = value[size:]
	}
	encoded := encodeUTF16LE(runes)
	clearRunes(runes)
	return encoded, nil
}

func clearRunes(value []rune) {
	for i := range value {
		value[i] = 0
	}
}

// tsRequestContainsOnlyVersionAndAuthInfo enforces the post-binding client
// message shape: credentials are the sole optional field after version.
func tsRequestContainsOnlyVersionAndAuthInfo(encoded []byte) bool {
	outer, rest, err := derRead(encoded)
	if err != nil || outer.tag != 0x30 || len(rest) != 0 {
		return false
	}
	seenVersion, seenAuthInfo := false, false
	for fields := outer.value; len(fields) > 0; {
		field, tail, err := derRead(fields)
		if err != nil {
			return false
		}
		switch field.tag {
		case 0xa0:
			if seenVersion {
				return false
			}
			seenVersion = true
		case 0xa2:
			if seenAuthInfo {
				return false
			}
			seenAuthInfo = true
		default:
			return false
		}
		fields = tail
	}
	return seenVersion && seenAuthInfo
}

func derExplicitOctetString(tag byte, value []byte) []byte {
	octets := derWrap(0x04, value)
	field := derWrap(tag, octets)
	clear(octets)
	return field
}

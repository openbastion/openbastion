package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/crypto/md4"
)

const (
	maxNTLMv2TargetInfo = 16 << 10
	maxNTLMv2AVPairs    = 64
	maxNTLMv2Password   = 1024
	maxNTLMv2Identity   = 256

	ntlmAvEOL             = 0x0000
	ntlmAvNbComputerName  = 0x0001
	ntlmAvNbDomainName    = 0x0002
	ntlmAvDNSComputerName = 0x0003
	ntlmAvDNSDomainName   = 0x0004
	ntlmAvDNSTreeName     = 0x0005
	ntlmAvFlags           = 0x0006
	ntlmAvTimestamp       = 0x0007
	ntlmAvSingleHost      = 0x0008
	ntlmAvTargetName      = 0x0009
	ntlmAvChannelBindings = 0x000a
	ntlmAvRestrictions    = 0xf000
)

var (
	ErrNTLMv2AVPair = errors.New("rdp: malformed NTLMv2 AV_PAIR list")
	ErrNTLMv2Input  = errors.New("rdp: invalid NTLMv2 input")
)

// NTLMv2AVPair is one validated target-info attribute. Value is an owned copy.
type NTLMv2AVPair struct {
	ID    uint16
	Value []byte
}

// NTLMv2Response contains the client responses and the session base key.
// Call Purge when the response is no longer needed; it clears key material held by this result.
// LMResponse contains the LMv2 proof, or Z(24) when the server supplied an AV timestamp.
type NTLMv2Response struct {
	NTProof        [16]byte
	NTResponse     []byte
	LMResponse     [24]byte
	SessionBaseKey [16]byte
	// ExportedSessionKey is random, and reaches the server as EncryptedRandomSessionKey: the
	// session keys do not derive from the password and the challenge alone (MS-NLMP 3.1.5.1.2).
	ExportedSessionKey        [16]byte
	EncryptedRandomSessionKey [16]byte
	serverChallenge           [8]byte
	valid                     bool
	// responseKey lets BindNTLMv2Response prove the blob as it is sent; boundServerInfo is the
	// server TargetInfo it was bound from: only a bound response authenticates.
	responseKey     [16]byte
	boundServerInfo []byte
}

// Purge overwrites response and key material held by the result.
func (r *NTLMv2Response) Purge() {
	if r == nil {
		return
	}
	clear(r.NTProof[:])
	clear(r.NTResponse)
	clear(r.LMResponse[:])
	clear(r.SessionBaseKey[:])
	clear(r.ExportedSessionKey[:])
	clear(r.EncryptedRandomSessionKey[:])
	clear(r.serverChallenge[:])
	clear(r.responseKey[:])
	clear(r.boundServerInfo)
	r.valid = false
}

// ParseNTLMv2AVPairs validates a complete AV_PAIR list, including its final
// zero-length EOL pair. Unknown IDs are preserved as opaque values for forward
// compatibility; duplicate IDs and malformed known attributes are rejected.
func ParseNTLMv2AVPairs(data []byte) ([]NTLMv2AVPair, error) {
	if len(data) < 4 || len(data) > maxNTLMv2TargetInfo {
		return nil, ErrNTLMv2AVPair
	}
	pairs := make([]NTLMv2AVPair, 0, 8)
	seen := make(map[uint16]struct{}, 8)
	for len(data) > 0 {
		if len(data) < 4 {
			return nil, ErrNTLMv2AVPair
		}
		id := binary.LittleEndian.Uint16(data[:2])
		length := int(binary.LittleEndian.Uint16(data[2:4]))
		data = data[4:]
		if length > len(data) {
			return nil, ErrNTLMv2AVPair
		}
		if id == ntlmAvEOL {
			if length != 0 || len(data) != 0 {
				return nil, ErrNTLMv2AVPair
			}
			return pairs, nil
		}
		if len(pairs) >= maxNTLMv2AVPairs {
			return nil, ErrNTLMv2AVPair
		}
		if _, exists := seen[id]; exists {
			return nil, ErrNTLMv2AVPair
		}
		seen[id] = struct{}{}
		value := data[:length]
		if !validNTLMv2AVValue(id, value) {
			return nil, ErrNTLMv2AVPair
		}
		pairs = append(pairs, NTLMv2AVPair{ID: id, Value: append([]byte(nil), value...)})
		data = data[length:]
	}
	return nil, ErrNTLMv2AVPair // EOL is mandatory, including for an empty list.
}

// NTLMv2ServerTargetInfoForProof validates and returns an owned, byte-for-byte
// copy of the server TargetInfo. NTProofStr is computed over these exact bytes;
// client AV_PAIRs and MIC_PRESENT are added to AUTHENTICATE only afterwards.
func NTLMv2ServerTargetInfoForProof(targetInfo []byte) ([]byte, error) {
	if _, err := ParseNTLMv2AVPairs(targetInfo); err != nil {
		return nil, err
	}
	return append([]byte(nil), targetInfo...), nil
}

func validNTLMv2AVValue(id uint16, value []byte) bool {
	switch id {
	case ntlmAvNbComputerName, ntlmAvNbDomainName, ntlmAvDNSComputerName, ntlmAvDNSDomainName, ntlmAvDNSTreeName, ntlmAvTargetName:
		return validUTF16LE(value)
	case ntlmAvFlags:
		return len(value) == 4
	case ntlmAvTimestamp:
		return len(value) == 8
	case ntlmAvSingleHost, ntlmAvRestrictions:
		return len(value) == 48
	case ntlmAvChannelBindings:
		return len(value) == 16
	default:
		return len(value) <= maxNTLMv2TargetInfo
	}
}

func validUTF16LE(data []byte) bool {
	if len(data)%2 != 0 {
		return false
	}
	units := make([]uint16, len(data)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	for i := 0; i < len(units); i++ {
		unit := units[i]
		switch {
		case unit >= 0xd800 && unit <= 0xdbff:
			if i+1 >= len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff {
				clear(units)
				return false
			}
			i++
		case unit >= 0xdc00 && unit <= 0xdfff:
			clear(units)
			return false
		}
	}
	clear(units)
	return true
}

// GenerateNTLMv2ClientChallenge returns an unpredictable eight-byte challenge.
// Callers must use this function (or crypto/rand) rather than a PRNG seeded by time.
func GenerateNTLMv2ClientChallenge() ([8]byte, error) {
	var challenge [8]byte
	if _, err := rand.Read(challenge[:]); err != nil {
		return [8]byte{}, err
	}
	return challenge, nil
}

// ComputeNTLMv2Response implements the NTLMv2 response calculation. timestamp
// is the eight-byte FILETIME value used in the NTLMv2 client-challenge blob.
// A server-supplied AV timestamp overrides timestamp. In that case LMResponse
// is Z(24), as required by MS-NLMP. Server-supplied target-name and channel-binding AV pairs are
// rejected; the client adds its own values after computing NTProof, from the
// pinned TLS peer. Only the MIC_PRESENT bit is recognized; the client sets it
// in AUTHENTICATE after computing NTProof.
// targetInfo must be a complete,
// validated AV_PAIR list. The caller owns password and should clear
// it after use. This function does not perform CredSSP or TLS key binding.
func ComputeNTLMv2Response(username, domain string, password []byte, serverChallenge, clientChallenge, timestamp [8]byte, targetInfo []byte) (NTLMv2Response, error) {
	var out NTLMv2Response
	if username == "" || !validNTLMv2Identity(username) || !validNTLMv2Identity(domain) || len(password) == 0 || len(password) > maxNTLMv2Password || !utf8.Valid(password) {
		return out, ErrNTLMv2Input
	}
	proofTargetInfo, err := NTLMv2ServerTargetInfoForProof(targetInfo)
	if err != nil {
		return out, err
	}
	defer clear(proofTargetInfo)
	pairs, err := ParseNTLMv2AVPairs(proofTargetInfo)
	if err != nil {
		return out, err
	}
	serverTimestamp := false
	effectiveTimestamp := timestamp
	for _, pair := range pairs {
		switch pair.ID {
		case ntlmAvTimestamp:
			copy(effectiveTimestamp[:], pair.Value)
			serverTimestamp = true
		case ntlmAvTargetName, ntlmAvChannelBindings:
			// These must be bound to the actual target and TLS channel, not echoed.
			return out, ErrNTLMv2Input
		case ntlmAvFlags:
			// MIC_PRESENT is set by the client after NTProof; unknown bits fail closed.
			if binary.LittleEndian.Uint32(pair.Value)&^uint32(0x00000002) != 0 {
				return out, ErrNTLMv2Input
			}
		}
	}

	responseKey, err := deriveNTLMv2ResponseKey(username, domain, password)
	if err != nil {
		return out, err
	}
	defer clear(responseKey[:])

	blob := make([]byte, 32+len(proofTargetInfo))
	blob[0], blob[1] = 1, 1 // RespType, HiRespType
	copy(blob[8:16], effectiveTimestamp[:])
	copy(blob[16:24], clientChallenge[:])
	copy(blob[28:], proofTargetInfo) // Reserved3 precedes AV pairs; the trailing four bytes are reserved.

	proofInput := make([]byte, 8+len(blob))
	copy(proofInput, serverChallenge[:])
	copy(proofInput[8:], blob)
	out.NTProof = hmacMD5(responseKey[:], proofInput)
	clear(proofInput)

	out.NTResponse = make([]byte, 16+len(blob))
	copy(out.NTResponse, out.NTProof[:])
	copy(out.NTResponse[16:], blob)
	clear(blob)

	if !serverTimestamp {
		lmInput := make([]byte, 16)
		copy(lmInput, serverChallenge[:])
		copy(lmInput[8:], clientChallenge[:])
		lmProof := hmacMD5(responseKey[:], lmInput)
		clear(lmInput)
		copy(out.LMResponse[:16], lmProof[:])
		copy(out.LMResponse[16:], clientChallenge[:])
		clear(lmProof[:])
	}

	out.SessionBaseKey = hmacMD5(responseKey[:], out.NTProof[:])
	out.serverChallenge = serverChallenge
	out.responseKey = responseKey
	out.valid = true
	return out, nil
}

// BindNTLMv2Response gives a response its final TargetInfo: the server's, with MsvAvFlags.MIC_PRESENT
// and, with bindings, the client's TargetName and TLS channel binding. NTProofStr and the session
// key are computed over those bytes, the ones sent: the server recomputes them from what it receives
// (MS-NLMP 3.1.5.1.2), so a proof over anything else cannot authenticate. The result owns its
// memory; purge both.
func BindNTLMv2Response(response NTLMv2Response, serverTargetInfo []byte, bindings *NTLMv2ClientBindings) (NTLMv2Response, error) {
	var out NTLMv2Response
	if !response.valid || allZero(response.responseKey[:]) || len(response.NTResponse) < 16+32+4 ||
		!bytes.Equal(response.NTResponse[16+28:len(response.NTResponse)-4], serverTargetInfo) {
		return out, ErrNTLMv2Input
	}
	var clientInfo []byte
	var err error
	if bindings != nil {
		clientInfo, err = NTLMv2TargetInfoWithClientBindings(serverTargetInfo, *bindings)
	} else {
		clientInfo, err = NTLMv2TargetInfoWithMICFlag(serverTargetInfo)
	}
	if err != nil {
		return out, err
	}
	defer clear(clientInfo)

	blob := make([]byte, 28+len(clientInfo)+4)
	copy(blob, response.NTResponse[16:16+28])
	copy(blob[28:], clientInfo)
	proofInput := make([]byte, 8+len(blob))
	copy(proofInput, response.serverChallenge[:])
	copy(proofInput[8:], blob)
	out.NTProof = hmacMD5(response.responseKey[:], proofInput)
	clear(proofInput)
	out.NTResponse = make([]byte, 16+len(blob))
	copy(out.NTResponse, out.NTProof[:])
	copy(out.NTResponse[16:], blob)
	clear(blob)
	out.LMResponse = response.LMResponse
	out.SessionBaseKey = hmacMD5(response.responseKey[:], out.NTProof[:])
	if _, err := rand.Read(out.ExportedSessionKey[:]); err != nil {
		out.Purge()
		return NTLMv2Response{}, ErrNTLMv2Input
	}
	keyExchange, err := rc4.NewCipher(out.SessionBaseKey[:])
	if err != nil {
		out.Purge()
		return NTLMv2Response{}, ErrNTLMv2Input
	}
	keyExchange.XORKeyStream(out.EncryptedRandomSessionKey[:], out.ExportedSessionKey[:])
	out.serverChallenge = response.serverChallenge
	out.boundServerInfo = append([]byte(nil), serverTargetInfo...)
	out.valid = true
	return out, nil
}

func deriveNTLMv2ResponseKey(username, domain string, password []byte) ([16]byte, error) {
	var key [16]byte
	passwordUTF16, ok := utf16LEFromUTF8(password)
	if !ok {
		return key, ErrNTLMv2Input
	}
	defer clear(passwordUTF16)
	var ntHash [16]byte
	md4Hash := md4.New()
	_, _ = md4Hash.Write(passwordUTF16)
	ntSum := md4Hash.Sum(nil)
	copy(ntHash[:], ntSum)
	clear(ntSum)
	defer clear(ntHash[:])

	identity := make([]byte, 0, (len(username)+len(domain))*2)
	identityRunes := make([]rune, 0, len(username)+len(domain))
	for _, r := range username {
		identityRunes = append(identityRunes, unicode.ToUpper(r))
	}
	for _, r := range domain {
		identityRunes = append(identityRunes, r)
	}
	units := utf16.Encode(identityRunes)
	clear(identityRunes)
	for _, unit := range units {
		identity = append(identity, byte(unit), byte(unit>>8))
	}
	clear(units)
	defer clear(identity)
	mac := hmac.New(md5.New, ntHash[:])
	_, _ = mac.Write(identity)
	sum := mac.Sum(nil)
	copy(key[:], sum)
	clear(sum)
	return key, nil
}

func utf16LEFromUTF8(value []byte) ([]byte, bool) {
	runes := make([]rune, 0, len(value))
	for len(value) > 0 {
		r, size := utf8.DecodeRune(value)
		if r == utf8.RuneError && size == 1 {
			clear(runes)
			return nil, false
		}
		runes = append(runes, r)
		value = value[size:]
	}
	units := utf16.Encode(runes)
	clear(runes)
	out := make([]byte, 0, len(units)*2)
	for _, unit := range units {
		out = append(out, byte(unit), byte(unit>>8))
	}
	clear(units)
	return out, true
}

func validNTLMv2Identity(value string) bool {
	if len(value) > maxNTLMv2Identity || !utf8.ValidString(value) {
		return false
	}
	for _, r := range value {
		if r == 0 {
			return false
		}
	}
	return true
}

func hmacMD5(key, data []byte) (out [16]byte) {
	mac := hmac.New(md5.New, key)
	_, _ = mac.Write(data)
	sum := mac.Sum(nil)
	copy(out[:], sum)
	clear(sum)
	return out
}

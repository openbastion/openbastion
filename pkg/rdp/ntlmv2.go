package rdp

import (
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
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

// NTLMv2TargetInfoForMIC validates that the server explicitly required an
// AUTHENTICATE_MESSAGE MIC and returns an owned, byte-for-byte copy of its
// TargetInfo. Client code must never synthesize or rewrite server AV_PAIRs:
// the NTProof is calculated over the exact TargetInfo sent in CHALLENGE_MESSAGE.
func NTLMv2TargetInfoForMIC(targetInfo []byte) ([]byte, error) {
	pairs, err := ParseNTLMv2AVPairs(targetInfo)
	if err != nil {
		return nil, err
	}
	flagsFound := false
	for _, pair := range pairs {
		if pair.ID != ntlmAvFlags {
			continue
		}
		flagsFound = true
		if binary.LittleEndian.Uint32(pair.Value) != 0x00000002 {
			return nil, ErrNTLMv2Input
		}
	}
	if !flagsFound {
		return nil, ErrNTLMv2Input
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
// is Z(24), as required by MS-NLMP. Target-name and channel-binding AV pairs are
// rejected until their TLS target/channel binding paths are complete. Only the
// MIC_PRESENT bit is recognized; the NTLMSSP MIC path requires the server to set it.
// targetInfo must be a complete,
// validated AV_PAIR list. The caller owns password and should clear
// it after use. This function does not perform CredSSP or TLS key binding.
func ComputeNTLMv2Response(username, domain string, password []byte, serverChallenge, clientChallenge, timestamp [8]byte, targetInfo []byte) (NTLMv2Response, error) {
	var out NTLMv2Response
	if username == "" || !validNTLMv2Identity(username) || !validNTLMv2Identity(domain) || len(password) == 0 || len(password) > maxNTLMv2Password || !utf8.Valid(password) {
		return out, ErrNTLMv2Input
	}
	pairs, err := ParseNTLMv2AVPairs(targetInfo)
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
			// MIC_PRESENT is supported by the NTLMSSP serializer; all other
			// flag bits remain refused until target-name binding is implemented.
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

	blob := make([]byte, 32+len(targetInfo))
	blob[0], blob[1] = 1, 1 // RespType, HiRespType
	copy(blob[8:16], effectiveTimestamp[:])
	copy(blob[16:24], clientChallenge[:])
	copy(blob[28:], targetInfo) // Reserved3 precedes AV pairs; the trailing four bytes are reserved.

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

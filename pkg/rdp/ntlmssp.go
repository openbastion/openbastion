package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"errors"
)

const (
	maxNTLMSSPMessage          = 64 << 10
	ntlmSSPNegotiateHeaderSize = 40
	ntlmSSPChallengeHeaderSize = 56
	ntlmSSPAuthHeaderSize      = 88

	ntlmSSPMessageNegotiate    = 1
	ntlmSSPMessageChallenge    = 2
	ntlmSSPMessageAuthenticate = 3

	ntlmSSPNegotiateUnicode                 = 0x00000001
	ntlmSSPRequestTarget                    = 0x00000004
	ntlmSSPNegotiateNTLM                    = 0x00000200
	ntlmSSPNegotiateAlwaysSign              = 0x00008000
	ntlmSSPNegotiateExtendedSessionSecurity = 0x00080000
	ntlmSSPNegotiateTargetInfo              = 0x00800000
	ntlmSSPTargetTypeDomain                 = 0x00010000
	ntlmSSPTargetTypeServer                 = 0x00020000

	ntlmSSPNegotiateFlags = ntlmSSPNegotiateUnicode |
		ntlmSSPRequestTarget |
		ntlmSSPNegotiateNTLM |
		ntlmSSPNegotiateAlwaysSign |
		ntlmSSPNegotiateExtendedSessionSecurity |
		ntlmSSPNegotiateTargetInfo
)

// ErrNTLMSSPMessage reports malformed messages or negotiation features outside the strict NTLMSSP profile.
var ErrNTLMSSPMessage = errors.New("rdp: malformed or unsupported NTLMSSP message")

var ntlmSSPSignature = []byte{'N', 'T', 'L', 'M', 'S', 'S', 'P', 0}

// NTLMSSPChallenge is a structurally validated server challenge. TargetInfo
// remains untrusted input; parsing it does not authenticate the server or
// establish TLS channel binding (ADR-0071).
type NTLMSSPChallenge struct {
	Flags           uint32
	ServerChallenge [8]byte
	TargetName      []byte // UTF-16LE, without a terminator
	TargetInfo      []byte // validated AV_PAIR encoding, still untrusted
}

// MarshalNTLMSSPNegotiate emits the one client profile supported by ADR-0071:
// Unicode, NTLM, extended session security, target info and always-sign. It
// deliberately does not request OEM, LM-key, NTLMv1, signing, sealing or key exchange.
func MarshalNTLMSSPNegotiate() []byte {
	message := make([]byte, ntlmSSPNegotiateHeaderSize)
	copy(message, ntlmSSPSignature)
	binary.LittleEndian.PutUint32(message[8:12], ntlmSSPMessageNegotiate)
	binary.LittleEndian.PutUint32(message[12:16], ntlmSSPNegotiateFlags)
	// Empty DomainName and Workstation security buffers point at the payload.
	binary.LittleEndian.PutUint32(message[20:24], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[28:32], uint32(len(message)))
	return message
}

// ParseNTLMSSPChallenge validates a CHALLENGE_MESSAGE against the exact
// OpenBastion client profile. Security-buffer offsets must stay outside the
// fixed header, in bounds and non-overlapping. Unknown negotiation features
// and protocol downgrades are rejected rather than negotiated opportunistically.
func ParseNTLMSSPChallenge(data []byte, offeredFlags uint32) (NTLMSSPChallenge, error) {
	var out NTLMSSPChallenge
	if len(data) < ntlmSSPChallengeHeaderSize || len(data) > maxNTLMSSPMessage || offeredFlags != ntlmSSPNegotiateFlags {
		return out, ErrNTLMSSPMessage
	}
	if !bytes.Equal(data[:8], ntlmSSPSignature) || binary.LittleEndian.Uint32(data[8:12]) != ntlmSSPMessageChallenge {
		return out, ErrNTLMSSPMessage
	}
	if !allZero(data[48:56]) { // VERSION was not negotiated; the fixed field must be zero.
		return out, ErrNTLMSSPMessage
	}
	flags := binary.LittleEndian.Uint32(data[20:24])
	required := uint32(ntlmSSPNegotiateUnicode | ntlmSSPNegotiateNTLM | ntlmSSPNegotiateAlwaysSign | ntlmSSPNegotiateExtendedSessionSecurity | ntlmSSPNegotiateTargetInfo)
	allowed := uint32(ntlmSSPNegotiateFlags | ntlmSSPTargetTypeDomain | ntlmSSPTargetTypeServer)
	if flags&required != required || flags&^allowed != 0 || flags&(ntlmSSPTargetTypeDomain|ntlmSSPTargetTypeServer) == ntlmSSPTargetTypeDomain|ntlmSSPTargetTypeServer {
		return out, ErrNTLMSSPMessage
	}

	targetName, targetRange, err := readNTLMSSPSecurityBuffer(data, 12, ntlmSSPChallengeHeaderSize)
	if err != nil || len(targetName) == 0 || len(targetName)%2 != 0 || targetRange[0]%2 != 0 || !validUTF16LE(targetName) {
		return out, ErrNTLMSSPMessage
	}
	targetInfo, infoRange, err := readNTLMSSPSecurityBuffer(data, 40, ntlmSSPChallengeHeaderSize)
	if err != nil || len(targetInfo) < 4 || len(targetInfo) > maxNTLMv2TargetInfo || rangesOverlap(targetRange, infoRange) {
		return out, ErrNTLMSSPMessage
	}
	if _, err := ParseNTLMv2AVPairs(targetInfo); err != nil {
		return out, ErrNTLMSSPMessage
	}
	copy(out.ServerChallenge[:], data[24:32])
	if out.ServerChallenge == ([8]byte{}) {
		return NTLMSSPChallenge{}, ErrNTLMSSPMessage
	}
	out.Flags = flags
	out.TargetName = append([]byte(nil), targetName...)
	out.TargetInfo = append([]byte(nil), targetInfo...)
	return out, nil
}

// MarshalNTLMSSPAuthenticate constructs a bounded NTLMv2 AUTHENTICATE_MESSAGE
// and computes its MIC over the exact NEGOTIATE, CHALLENGE and zero-MIC
// AUTHENTICATE messages. The current profile includes the computed LMv2 response
// (server timestamps are refused until the Z(24) path is implemented) and omits
// EncryptedRandomSessionKey because KEY_EXCH is not negotiated. This is a codec
// primitive only; it does not perform CredSSP, verify the TLS peer or transmit
// credentials. The caller must enforce the TLS pin and clear the returned bytes.
func MarshalNTLMSSPAuthenticate(negotiateMessage, challengeMessage []byte, username, domain string, response NTLMv2Response) ([]byte, error) {
	if !bytes.Equal(negotiateMessage, MarshalNTLMSSPNegotiate()) || username == "" || !validNTLMv2Identity(username) || !validNTLMv2Identity(domain) {
		return nil, ErrNTLMSSPMessage
	}
	challenge, err := ParseNTLMSSPChallenge(challengeMessage, ntlmSSPNegotiateFlags)
	if err != nil {
		return nil, err
	}
	if err := validateNTLMv2ResponseForChallenge(response, challenge); err != nil {
		return nil, err
	}
	userBytes, ok := utf16LEFromUTF8([]byte(username))
	if !ok || len(userBytes) > 0xffff {
		return nil, ErrNTLMSSPMessage
	}
	defer clear(userBytes)
	domainBytes, ok := utf16LEFromUTF8([]byte(domain))
	if !ok || len(domainBytes) > 0xffff {
		return nil, ErrNTLMSSPMessage
	}
	defer clear(domainBytes)

	message := make([]byte, ntlmSSPAuthHeaderSize)
	copy(message, ntlmSSPSignature)
	binary.LittleEndian.PutUint32(message[8:12], ntlmSSPMessageAuthenticate)
	binary.LittleEndian.PutUint32(message[60:64], challenge.Flags)
	// Version is all zero because NEGOTIATE_VERSION was not offered.
	payloadOffset := uint32(len(message))
	setNTLMSSPSecurityBuffer(message[12:20], payloadOffset, response.LMResponse[:])
	message = append(message, response.LMResponse[:]...)
	payloadOffset = uint32(len(message))
	setNTLMSSPSecurityBuffer(message[20:28], payloadOffset, response.NTResponse)
	message = append(message, response.NTResponse...)
	if len(message)%2 != 0 {
		message = append(message, 0) // Unicode payload offsets must be 16-bit aligned.
	}
	payloadOffset = uint32(len(message))
	setNTLMSSPSecurityBuffer(message[28:36], payloadOffset, domainBytes)
	message = append(message, domainBytes...)
	payloadOffset = uint32(len(message))
	setNTLMSSPSecurityBuffer(message[36:44], payloadOffset, userBytes)
	message = append(message, userBytes...)
	payloadOffset = uint32(len(message))
	setNTLMSSPSecurityBuffer(message[44:52], payloadOffset, nil) // Workstation is not supplied.
	setNTLMSSPSecurityBuffer(message[52:60], payloadOffset, nil) // KEY_EXCH is not negotiated.
	if len(message) > maxNTLMSSPMessage {
		clear(message)
		return nil, ErrNTLMSSPMessage
	}

	mac := hmac.New(md5.New, response.SessionBaseKey[:])
	_, _ = mac.Write(negotiateMessage)
	_, _ = mac.Write(challengeMessage)
	_, _ = mac.Write(message) // MIC field remains zero during calculation.
	mic := mac.Sum(nil)
	copy(message[72:88], mic)
	clear(mic)
	return message, nil
}

func validateNTLMv2ResponseForChallenge(response NTLMv2Response, challenge NTLMSSPChallenge) error {
	if len(response.NTResponse) < 16+32+4 || len(response.NTResponse) > 16+32+maxNTLMv2TargetInfo || allZero(response.NTProof[:]) || allZero(response.LMResponse[:16]) || allZero(response.SessionBaseKey[:]) || !hmac.Equal(response.NTProof[:], response.NTResponse[:16]) {
		return ErrNTLMSSPMessage
	}
	blob := response.NTResponse[16:]
	if blob[0] != 1 || blob[1] != 1 || !allZero(blob[2:8]) || !allZero(blob[24:28]) || !allZero(blob[len(blob)-4:]) || !hmac.Equal(response.LMResponse[16:], blob[16:24]) {
		return ErrNTLMSSPMessage
	}
	targetInfo := blob[28 : len(blob)-4]
	wantTargetInfo, err := NTLMv2TargetInfoWithMICFlag(challenge.TargetInfo)
	if err != nil {
		return ErrNTLMSSPMessage
	}
	defer clear(wantTargetInfo)
	if !bytes.Equal(targetInfo, wantTargetInfo) {
		return ErrNTLMSSPMessage
	}
	pairs, err := ParseNTLMv2AVPairs(targetInfo)
	if err != nil {
		return ErrNTLMSSPMessage
	}
	for _, pair := range pairs {
		switch pair.ID {
		case ntlmAvTimestamp, ntlmAvTargetName, ntlmAvChannelBindings:
			// Timestamp needs Z(24)/clock handling; target-name and channel-binding
			// AV pairs must be derived from the pinned TLS peer, not echoed blindly.
			return ErrNTLMSSPMessage
		case ntlmAvFlags:
			if binary.LittleEndian.Uint32(pair.Value) != 0x00000002 {
				return ErrNTLMSSPMessage
			}
		}
	}
	return nil
}

func readNTLMSSPSecurityBuffer(message []byte, fieldOffset, headerSize int) ([]byte, [2]int, error) {
	var empty [2]int
	if fieldOffset < 0 || fieldOffset+8 > len(message) {
		return nil, empty, ErrNTLMSSPMessage
	}
	length := uint64(binary.LittleEndian.Uint16(message[fieldOffset : fieldOffset+2]))
	offset := uint64(binary.LittleEndian.Uint32(message[fieldOffset+4 : fieldOffset+8]))
	if length == 0 {
		return []byte{}, empty, nil // Offset and MaxLen are ignored for an empty field.
	}
	end := offset + length
	if offset < uint64(headerSize) || end < offset || end > uint64(len(message)) {
		return nil, empty, ErrNTLMSSPMessage
	}
	return message[int(offset):int(end)], [2]int{int(offset), int(end)}, nil
}

func setNTLMSSPSecurityBuffer(field []byte, offset uint32, value []byte) {
	binary.LittleEndian.PutUint16(field[0:2], uint16(len(value)))
	binary.LittleEndian.PutUint16(field[2:4], uint16(len(value)))
	binary.LittleEndian.PutUint32(field[4:8], offset)
}

func rangesOverlap(first, second [2]int) bool {
	return first[0] != first[1] && second[0] != second[1] && first[0] < second[1] && second[0] < first[1]
}

func allZero(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

package rdp

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"testing"
)

func TestMarshalNTLMSSPNegotiate_UsesStrictClientProfile(t *testing.T) {
	message := MarshalNTLMSSPNegotiate()
	if len(message) != ntlmSSPNegotiateHeaderSize || !bytes.Equal(message[:8], ntlmSSPSignature) {
		t.Fatalf("unexpected NEGOTIATE_MESSAGE: %x", message)
	}
	if got := binary.LittleEndian.Uint32(message[8:12]); got != ntlmSSPMessageNegotiate {
		t.Fatalf("message type = %d, want %d", got, ntlmSSPMessageNegotiate)
	}
	if got := binary.LittleEndian.Uint32(message[12:16]); got != ntlmSSPNegotiateFlags {
		t.Fatalf("flags = %#08x, want %#08x", got, ntlmSSPNegotiateFlags)
	}
	if !allZero(message[16:20]) || !allZero(message[24:28]) {
		t.Fatal("NEGOTIATE_MESSAGE unexpectedly supplies a domain or workstation")
	}
	if !bytes.Equal(message[32:40], ntlmSSPClientVersion) {
		t.Fatal("NEGOTIATE_MESSAGE must carry the Version it negotiates")
	}
}

func TestParseNTLMSSPChallenge_Valid(t *testing.T) {
	targetInfo := ntlmSSPTestTargetInfo(t)
	message := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
	got, err := ParseNTLMSSPChallenge(message, ntlmSSPNegotiateFlags)
	if err != nil {
		t.Fatal(err)
	}
	if got.Flags != ntlmSSPNegotiateFlags || got.ServerChallenge != mustHex8(t, "0123456789abcdef") {
		t.Fatalf("unexpected challenge fields: %#v", got)
	}
	if !bytes.Equal(got.TargetInfo, targetInfo) || !bytes.Equal(got.TargetName, []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0}) {
		t.Fatalf("unexpected target fields: %#v", got)
	}
}

func TestParseNTLMSSPChallenge_RejectsDowngradeAndMalformedBuffers(t *testing.T) {
	targetInfo := ntlmSSPTestTargetInfo(t)
	base := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
	cases := map[string]func([]byte) []byte{
		"signature":    func(b []byte) []byte { b[0] ^= 0xff; return b },
		"message type": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[8:12], ntlmSSPMessageAuthenticate); return b },
		"missing extended session security": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[20:24], ntlmSSPNegotiateFlags&^ntlmSSPNegotiateExtendedSessionSecurity)
			return b
		},
		"key exchange downgrade": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[20:24], ntlmSSPNegotiateFlags&^ntlmSSPNegotiateKeyExchange)
			return b
		},
		"target name points into header": func(b []byte) []byte { binary.LittleEndian.PutUint32(b[16:20], 20); return b },
		"target info out of bounds":      func(b []byte) []byte { binary.LittleEndian.PutUint32(b[44:48], uint32(len(b)+4)); return b },
		"overlapping buffers": func(b []byte) []byte {
			binary.LittleEndian.PutUint32(b[44:48], binary.LittleEndian.Uint32(b[16:20]))
			return b
		},
		"odd unicode target name": func(b []byte) []byte {
			binary.LittleEndian.PutUint16(b[12:14], 3)
			binary.LittleEndian.PutUint16(b[14:16], 3)
			return b
		},
		"unaligned unicode target name": func(b []byte) []byte {
			shifted := make([]byte, len(b)+1)
			copy(shifted, b[:ntlmSSPChallengeHeaderSize])
			copy(shifted[ntlmSSPChallengeHeaderSize+1:], b[ntlmSSPChallengeHeaderSize:])
			binary.LittleEndian.PutUint32(shifted[16:20], ntlmSSPChallengeHeaderSize+1)
			binary.LittleEndian.PutUint32(shifted[44:48], uint32(ntlmSSPChallengeHeaderSize+1+12))
			return shifted
		},
		"zero server challenge": func(b []byte) []byte { clear(b[24:32]); return b },
		"malformed target info": func(b []byte) []byte { b[len(b)-1] = 1; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			input := mutate(append([]byte(nil), base...))
			if _, err := ParseNTLMSSPChallenge(input, ntlmSSPNegotiateFlags); !errors.Is(err, ErrNTLMSSPMessage) {
				t.Fatalf("ParseNTLMSSPChallenge() error = %v, want ErrNTLMSSPMessage", err)
			}
		})
	}
	if _, err := ParseNTLMSSPChallenge(base, ntlmSSPNegotiateFlags|0x40); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("unoffered client flags error = %v, want ErrNTLMSSPMessage", err)
	}
}

func TestMarshalNTLMSSPAuthenticate_ComputesMICIncludesLMv2AndTheExchangedKey(t *testing.T) {
	negotiate := MarshalNTLMSSPNegotiate()
	targetInfo := ntlmSSPTestTargetInfo(t)
	challenge := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
	response := ntlmSSPTestResponse(t, targetInfo)
	defer response.Purge()

	message, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "User", "Domain", response)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(message)
	if len(message) < ntlmSSPAuthHeaderSize || !bytes.Equal(message[:8], ntlmSSPSignature) || binary.LittleEndian.Uint32(message[8:12]) != ntlmSSPMessageAuthenticate {
		t.Fatalf("malformed AUTHENTICATE_MESSAGE header: %x", message[:min(len(message), ntlmSSPAuthHeaderSize)])
	}
	if binary.LittleEndian.Uint16(message[12:14]) != 24 || binary.LittleEndian.Uint16(message[52:54]) != 16 {
		t.Fatal("expected a 24-byte LMv2 response")
	}
	encrypted, _, err := readNTLMSSPSecurityBuffer(message, 52, ntlmSSPAuthHeaderSize)
	if err != nil || !bytes.Equal(encrypted, response.EncryptedRandomSessionKey[:]) || bytes.Equal(encrypted, response.ExportedSessionKey[:]) {
		t.Fatalf("EncryptedRandomSessionKey = %x, %v", encrypted, err)
	}
	lmResponse, _, err := readNTLMSSPSecurityBuffer(message, 12, ntlmSSPAuthHeaderSize)
	if err != nil || !bytes.Equal(lmResponse, response.LMResponse[:]) {
		t.Fatalf("LMv2 response security buffer = %x, %v", lmResponse, err)
	}
	if !bytes.Equal(message[64:72], ntlmSSPClientVersion) || allZero(message[72:88]) {
		t.Fatal("expected the client Version and a populated MIC")
	}
	ntResponse, _, err := readNTLMSSPSecurityBuffer(message, 20, ntlmSSPAuthHeaderSize)
	if err != nil || !bytes.Equal(ntResponse, response.NTResponse) {
		t.Fatalf("NT response security buffer = %x, %v", ntResponse, err)
	}
	domain, _, err := readNTLMSSPSecurityBuffer(message, 28, ntlmSSPAuthHeaderSize)
	if err != nil || !bytes.Equal(domain, []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0}) {
		t.Fatalf("domain security buffer = %x, %v", domain, err)
	}
	user, _, err := readNTLMSSPSecurityBuffer(message, 36, ntlmSSPAuthHeaderSize)
	if err != nil || !bytes.Equal(user, []byte{'U', 0, 's', 0, 'e', 0, 'r', 0}) {
		t.Fatalf("user security buffer = %x, %v", user, err)
	}

	withoutMIC := append([]byte(nil), message...)
	defer clear(withoutMIC)
	wantMIC := append([]byte(nil), message[72:88]...)
	defer clear(wantMIC)
	clear(withoutMIC[72:88])
	mac := hmac.New(md5.New, response.ExportedSessionKey[:])
	_, _ = mac.Write(negotiate)
	_, _ = mac.Write(challenge)
	_, _ = mac.Write(withoutMIC)
	if !hmac.Equal(wantMIC, mac.Sum(nil)) {
		t.Fatal("AUTHENTICATE_MESSAGE MIC does not cover the exact negotiation transcript")
	}
}

func TestMarshalNTLMSSPAuthenticate_UsesServerTimestampAndZ24(t *testing.T) {
	baseTargetInfo := ntlmSSPTestTargetInfo(t)
	serverTimestamp := mustHex8(t, "8877665544332211")
	targetInfo := append([]byte{ntlmAvTimestamp, 0, 8, 0}, serverTimestamp[:]...)
	targetInfo = append(targetInfo, baseTargetInfo...)
	challenge := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
	responseTargetInfo, err := NTLMv2ServerTargetInfoForProof(targetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseTargetInfo)
	password := []byte("Password")
	response, err := ComputeNTLMv2Response("User", "Domain", password, mustHex8(t, "0123456789abcdef"), mustHex8(t, "aaaaaaaaaaaaaaaa"), mustHex8(t, "0000000000000000"), responseTargetInfo)
	clear(password)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Purge()
	if !allZero(response.LMResponse[:]) || !bytes.Equal(response.NTResponse[24:32], serverTimestamp[:]) {
		t.Fatalf("NTLMv2 response did not use server timestamp/Z(24): timestamp=%x LM=%x", response.NTResponse[24:32], response.LMResponse)
	}
	response = ntlmSSPBound(t, response, responseTargetInfo, nil)
	defer response.Purge()
	message, err := MarshalNTLMSSPAuthenticate(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", response)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(message)
	lmResponse, _, err := readNTLMSSPSecurityBuffer(message, 12, ntlmSSPAuthHeaderSize)
	if err != nil || len(lmResponse) != 24 || !allZero(lmResponse) {
		t.Fatalf("AUTHENTICATE_MESSAGE LMChallengeResponse = %x, %v; want Z(24)", lmResponse, err)
	}
	response.LMResponse[0] = 1
	if _, err := MarshalNTLMSSPAuthenticate(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("nonzero LM response with server timestamp error = %v, want ErrNTLMSSPMessage", err)
	}
	response.LMResponse[0] = 0
	tampered := response
	tampered.NTResponse = append([]byte(nil), response.NTResponse...)
	tampered.NTResponse[16+8] ^= 1
	if _, err := MarshalNTLMSSPAuthenticate(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", tampered); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("blob timestamp not bound to server AV timestamp error = %v, want ErrNTLMSSPMessage", err)
	}
	clear(tampered.NTResponse)
}

func TestMarshalNTLMSSPAuthenticate_RejectsTamperedTranscriptAndResponse(t *testing.T) {
	negotiate := MarshalNTLMSSPNegotiate()
	targetInfo := ntlmSSPTestTargetInfo(t)
	challenge := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
	response := ntlmSSPTestResponse(t, targetInfo)
	defer response.Purge()
	if _, err := MarshalNTLMSSPAuthenticate(append(negotiate, 0), challenge, "User", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("tampered NEGOTIATE_MESSAGE error = %v", err)
	}
	if _, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("empty username error = %v", err)
	}
	response.LMResponse[16] ^= 1
	if _, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "User", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("mismatched LMv2 client challenge error = %v", err)
	}
	response.LMResponse[16] ^= 1
	response.NTResponse[0] ^= 1
	if _, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "User", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("mismatched NT proof error = %v", err)
	}
	response.NTResponse[0] ^= 1
	response.NTResponse[16+28] ^= 1 // alter the first AV_PAIR ID without changing the challenge
	if _, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "User", "Domain", response); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("mismatched TargetInfo error = %v", err)
	}

	password := []byte("Password")
	targetInfoWithoutMIC := targetInfo[8:] // Test fixture starts with the server's MsvAvFlags pair.
	challengeWithoutMIC := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfoWithoutMIC)
	plainResponse, err := ComputeNTLMv2Response("User", "Domain", password, mustHex8(t, "0123456789abcdef"), mustHex8(t, "aaaaaaaaaaaaaaaa"), mustHex8(t, "0000000000000000"), targetInfoWithoutMIC)
	clear(password)
	if err != nil {
		t.Fatal(err)
	}
	defer plainResponse.Purge()
	plainResponse = ntlmSSPBound(t, plainResponse, targetInfoWithoutMIC, nil)
	defer plainResponse.Purge()
	messageWithoutServerFlag, err := MarshalNTLMSSPAuthenticate(negotiate, challengeWithoutMIC, "User", "Domain", plainResponse)
	if err != nil {
		t.Fatalf("client should set MIC_PRESENT after NTProof when server omitted it: %v", err)
	}
	ntResponseWithoutServerFlag, _, err := readNTLMSSPSecurityBuffer(messageWithoutServerFlag, 20, ntlmSSPAuthHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	pairsWithoutServerFlag, err := ParseNTLMv2AVPairs(ntResponseWithoutServerFlag[16+28 : len(ntResponseWithoutServerFlag)-4])
	if err != nil {
		t.Fatal(err)
	}
	foundMICFlag := false
	for _, pair := range pairsWithoutServerFlag {
		if pair.ID == ntlmAvFlags && binary.LittleEndian.Uint32(pair.Value) == 0x00000002 {
			foundMICFlag = true
		}
	}
	clear(messageWithoutServerFlag)
	if !foundMICFlag {
		t.Fatal("AUTHENTICATE TargetInfo omitted client MIC_PRESENT flag")
	}
	zeroKeyResponse := ntlmSSPTestResponse(t, targetInfo)
	defer zeroKeyResponse.Purge()
	clear(zeroKeyResponse.SessionBaseKey[:])
	if _, err := MarshalNTLMSSPAuthenticate(negotiate, challenge, "User", "Domain", zeroKeyResponse); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("zero session base key error = %v", err)
	}
}

func FuzzParseNTLMSSPChallenge(f *testing.F) {
	targetInfo, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	f.Add(ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo))
	f.Add([]byte("NTLMSSP\x00"))
	f.Fuzz(func(t *testing.T, data []byte) {
		challenge, err := ParseNTLMSSPChallenge(data, ntlmSSPNegotiateFlags)
		if err == nil {
			if len(challenge.TargetInfo) > maxNTLMv2TargetInfo || len(challenge.TargetName) == 0 || challenge.ServerChallenge == ([8]byte{}) {
				t.Fatalf("parser returned invalid challenge: %#v", challenge)
			}
		}
	})
}

func ntlmSSPTestTargetInfo(t *testing.T) []byte {
	t.Helper()
	value, err := hex.DecodeString("060004000200000002000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	if err != nil {
		t.Fatal(err)
	}
	return value
}

func ntlmSSPTestChallenge(flags uint32, targetInfo []byte) []byte {
	targetName := []byte{'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0}
	message := make([]byte, ntlmSSPChallengeHeaderSize)
	copy(message, ntlmSSPSignature)
	binary.LittleEndian.PutUint32(message[8:12], ntlmSSPMessageChallenge)
	binary.LittleEndian.PutUint16(message[12:14], uint16(len(targetName)))
	binary.LittleEndian.PutUint16(message[14:16], uint16(len(targetName)))
	binary.LittleEndian.PutUint32(message[16:20], uint32(len(message)))
	binary.LittleEndian.PutUint32(message[20:24], flags)
	challenge, _ := hex.DecodeString("0123456789abcdef")
	copy(message[24:32], challenge)
	binary.LittleEndian.PutUint16(message[40:42], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint16(message[42:44], uint16(len(targetInfo)))
	binary.LittleEndian.PutUint32(message[44:48], uint32(len(message)+len(targetName)))
	message = append(message, targetName...)
	message = append(message, targetInfo...)
	return message
}

func ntlmSSPTestResponse(t *testing.T, targetInfo []byte) NTLMv2Response {
	t.Helper()
	password := []byte("Password")
	defer clear(password)
	responseTargetInfo, err := NTLMv2ServerTargetInfoForProof(targetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseTargetInfo)
	returnValue, err := ComputeNTLMv2Response("User", "Domain", password, mustHex8(t, "0123456789abcdef"), mustHex8(t, "aaaaaaaaaaaaaaaa"), mustHex8(t, "0000000000000000"), responseTargetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer returnValue.Purge()
	return ntlmSSPBound(t, returnValue, responseTargetInfo, nil)
}

func ntlmSSPBound(t *testing.T, response NTLMv2Response, serverInfo []byte, bindings *NTLMv2ClientBindings) NTLMv2Response {
	t.Helper()
	bound, err := BindNTLMv2Response(response, serverInfo, bindings)
	if err != nil {
		t.Fatal(err)
	}
	return bound
}

func TestMarshalNTLMSSPAuthenticate_AlignsUnicodePayloadAfterOddTargetInfo(t *testing.T) {
	base := ntlmSSPTestTargetInfo(t)
	oddTargetInfo := append(append([]byte(nil), base[:len(base)-4]...), 0x34, 0x12, 1, 0, 0x7f)
	oddTargetInfo = append(oddTargetInfo, base[len(base)-4:]...)
	challenge := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, oddTargetInfo)
	responseTargetInfo, err := NTLMv2ServerTargetInfoForProof(oddTargetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(responseTargetInfo)
	password := []byte("Password")
	response, err := ComputeNTLMv2Response("User", "Domain", password, mustHex8(t, "0123456789abcdef"), mustHex8(t, "aaaaaaaaaaaaaaaa"), mustHex8(t, "0000000000000000"), responseTargetInfo)
	clear(password)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Purge()
	response = ntlmSSPBound(t, response, responseTargetInfo, nil)
	defer response.Purge()
	message, err := MarshalNTLMSSPAuthenticate(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", response)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(message)
	for _, field := range []int{28, 36} {
		_, span, err := readNTLMSSPSecurityBuffer(message, field, ntlmSSPAuthHeaderSize)
		if err != nil || span[0]%2 != 0 {
			t.Fatalf("Unicode security buffer at field %d is not aligned: span=%v err=%v", field, span, err)
		}
	}
}

func TestMarshalNTLMSSPAuthenticateWithBindings_BindsTargetAndTLSChannel(t *testing.T) {
	challenge := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, ntlmSSPTestTargetInfo(t))
	parsed, err := ParseNTLMSSPChallenge(challenge, ntlmSSPNegotiateFlags)
	if err != nil {
		t.Fatal(err)
	}
	password := []byte("Password")
	defer clear(password)
	response, err := ComputeNTLMv2Response("User", "Domain", password, parsed.ServerChallenge, mustHex8(t, "aaaaaaaaaaaaaaaa"), mustHex8(t, "0000000000000000"), parsed.TargetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Purge()
	name, err := NTLMv2TargetName("rdp.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(name)
	bindings := NTLMv2ClientBindings{TargetName: name, ChannelBindings: mustHex16(t, "00112233445566778899aabbccddeeff")}
	wantInfo, err := NTLMv2TargetInfoWithClientBindings(parsed.TargetInfo, bindings)
	if err != nil {
		t.Fatal(err)
	}
	unbound := response
	response = ntlmSSPBound(t, unbound, parsed.TargetInfo, &bindings)
	defer response.Purge()
	if !bytes.Equal(response.NTResponse[16+28:len(response.NTResponse)-4], wantInfo) {
		t.Fatalf("the proof does not cover the TargetInfo that is sent")
	}
	clear(wantInfo)
	message, err := MarshalNTLMSSPAuthenticateWithBindings(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", response, bindings)
	if err != nil {
		t.Fatalf("marshal with bindings: %v", err)
	}
	defer clear(message)
	ntResponse, _, err := readNTLMSSPSecurityBuffer(message, 20, ntlmSSPAuthHeaderSize)
	if err != nil {
		t.Fatal(err)
	}
	blobTargetInfo := ntResponse[16+28 : len(ntResponse)-4]
	pairs, err := ParseNTLMv2AVPairs(blobTargetInfo)
	if err != nil {
		t.Fatal(err)
	}
	if pairs[len(pairs)-2].ID != ntlmAvChannelBindings || !bytes.Equal(pairs[len(pairs)-2].Value, bindings.ChannelBindings[:]) || pairs[len(pairs)-1].ID != ntlmAvTargetName || !bytes.Equal(pairs[len(pairs)-1].Value, name) {
		t.Fatalf("AUTHENTICATE client AV_PAIRs = %#v", pairs)
	}
	for label, changed := range map[string]NTLMv2ClientBindings{
		"target substitution":  {TargetName: mustUTF16LE(t, "TERMSRV/other.example.test"), ChannelBindings: bindings.ChannelBindings},
		"channel substitution": {TargetName: name, ChannelBindings: mustHex16(t, "ffeeddccbbaa99887766554433221100")},
	} {
		t.Run(label, func(t *testing.T) {
			tampered := response
			tampered.NTResponse = append([]byte(nil), ntResponse...)
			defer clear(tampered.NTResponse)
			if err := validateNTLMv2ResponseForChallenge(tampered, parsed, &changed); !errors.Is(err, ErrNTLMSSPMessage) {
				t.Fatalf("substituted binding validation error = %v, want ErrNTLMSSPMessage", err)
			}
			// The proof is bound to its target and channel: it does not serve for another.
			if _, err := MarshalNTLMSSPAuthenticateWithBindings(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", response, changed); !errors.Is(err, ErrNTLMSSPMessage) {
				t.Fatalf("a proof for another binding error = %v, want ErrNTLMSSPMessage", err)
			}
			rebound := ntlmSSPBound(t, unbound, parsed.TargetInfo, &changed)
			defer rebound.Purge()
			if rebound.NTProof == response.NTProof || rebound.SessionBaseKey == response.SessionBaseKey {
				t.Fatal("the proof and the session key do not depend on the binding")
			}
			other, err := MarshalNTLMSSPAuthenticateWithBindings(MarshalNTLMSSPNegotiate(), challenge, "User", "Domain", rebound, changed)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(other)
			if bytes.Equal(other, message) {
				t.Fatal("substituted binding did not change AUTHENTICATE transcript")
			}
		})
	}
}

func mustUTF16LE(t *testing.T, value string) []byte {
	t.Helper()
	encoded, ok := utf16LEFromUTF8([]byte(value))
	if !ok {
		t.Fatalf("cannot encode %q", value)
	}
	return encoded
}

// The MIC sits at 72 only when VERSION is agreed: a server that does not echo it would read the MIC
// elsewhere, so the session is refused rather than proved against the wrong bytes.
func TestParseNTLMSSPChallenge_VersionMustBeAgreed(t *testing.T) {
	info := []byte{1, 0, 2, 0, 'S', 0, 0, 0, 0, 0}
	flags := uint32(ntlmSSPNegotiateFlags)
	if _, err := ParseNTLMSSPChallenge(ntlmSSPTestChallenge(flags, info), ntlmSSPNegotiateFlags); err != nil {
		t.Fatalf("agreed: %v", err)
	}
	if _, err := ParseNTLMSSPChallenge(ntlmSSPTestChallenge(flags&^ntlmSSPNegotiateVersion, info), ntlmSSPNegotiateFlags); !errors.Is(err, ErrNTLMSSPMessage) {
		t.Fatalf("not echoed: %v", err)
	}
}

// What a server recomputes from AUTHENTICATE (MS-NLMP 3.2.5.1.2) must be what the client proved and
// keyed with: a proof over the server's TargetInfo alone leaves both sides with different keys.
func TestBindNTLMv2Response_TheProofCoversTheBlobThatIsSent(t *testing.T) {
	info := ntlmSSPTestTargetInfo(t)
	response := ntlmSSPTestResponse(t, info)
	defer response.Purge()
	password := []byte("Password")
	defer clear(password)
	key, err := deriveNTLMv2ResponseKey("User", "Domain", password)
	if err != nil {
		t.Fatal(err)
	}
	challenge := mustHex8(t, "0123456789abcdef")
	proof := hmacMD5(key[:], append(challenge[:], response.NTResponse[16:]...))
	if proof != response.NTProof || !bytes.Equal(response.NTResponse[:16], proof[:]) {
		t.Fatal("NTProofStr does not cover the blob that is sent")
	}
	if want := hmacMD5(key[:], proof[:]); want != response.SessionBaseKey {
		t.Fatal("the session key is not the one a server derives")
	}
}

// KEY_EXCH is worth something only if the key is the client's own random: two bindings of one proof
// never share it, and it is not the key that derives from the password.
func TestBindNTLMv2Response_TheExchangedKeyIsRandom(t *testing.T) {
	info := ntlmSSPTestTargetInfo(t)
	first := ntlmSSPTestResponse(t, info)
	defer first.Purge()
	second := ntlmSSPTestResponse(t, info)
	defer second.Purge()
	if first.SessionBaseKey != second.SessionBaseKey {
		t.Fatal("the same inputs should give the same base key: this test compares nothing else")
	}
	if first.ExportedSessionKey == second.ExportedSessionKey || first.ExportedSessionKey == first.SessionBaseKey {
		t.Fatal("the exported session key is not random")
	}
}

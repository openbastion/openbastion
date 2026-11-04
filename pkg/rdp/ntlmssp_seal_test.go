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

func ntlmSSPSecurityContexts(t *testing.T) (*NTLMSSPClientSecurityContext, *NTLMSSPClientSecurityContext) {
	t.Helper()
	flags := ntlmSSPNegotiateFlags | ntlmSSPTargetTypeServer
	challengeBytes := ntlmSSPTestChallenge(flags, ntlmSSPTestTargetInfo(t))
	challenge, err := ParseNTLMSSPChallenge(challengeBytes, ntlmSSPNegotiateFlags)
	if err != nil {
		t.Fatal(err)
	}
	response := ntlmSSPTestResponse(t, ntlmSSPTestTargetInfo(t))
	t.Cleanup(func() { response.Purge() })
	client, err := NewNTLMSSPClientSecurityContext(response, challenge)
	if err != nil {
		t.Fatal(err)
	}
	server, err := newNTLMSSPSecurityContext(response.SessionBaseKey, challenge.Flags, false)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	t.Cleanup(server.Close)
	return client, server
}

func TestNTLMSSPSecurityContextWrapUnwrapUsesIndependentDirections(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	first := []byte("CredSSP client public-key hash")
	second := []byte("second client message")

	wrappedFirst, err := client.WrapClientToServer(first)
	if err != nil {
		t.Fatal(err)
	}
	wrappedSecond, err := client.WrapClientToServer(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(wrappedFirst) != 16+len(first) {
		t.Fatalf("wrapped length = %d, want %d", len(wrappedFirst), 16+len(first))
	}
	if got := binary.LittleEndian.Uint32(wrappedFirst[:4]); got != 1 {
		t.Fatalf("signature version = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(wrappedFirst[12:16]); got != 0 {
		t.Fatalf("first sequence = %d, want 0", got)
	}
	if got := binary.LittleEndian.Uint32(wrappedSecond[12:16]); got != 1 {
		t.Fatalf("second sequence = %d, want 1", got)
	}
	if bytes.Equal(wrappedFirst[16:], first) {
		t.Fatal("sealed payload is plaintext")
	}
	gotFirst, err := server.inbound.unwrap(wrappedFirst)
	if err != nil || !bytes.Equal(gotFirst, first) {
		t.Fatalf("first unwrap = %q, %v", gotFirst, err)
	}
	gotSecond, err := server.inbound.unwrap(wrappedSecond)
	if err != nil || !bytes.Equal(gotSecond, second) {
		t.Fatalf("second unwrap = %q, %v", gotSecond, err)
	}

	serverReply := []byte("CredSSP server public-key proof")
	wrappedReply, err := server.outbound.wrap(serverReply)
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.LittleEndian.Uint32(wrappedReply[12:16]); got != 0 {
		t.Fatalf("server first sequence = %d, want 0", got)
	}
	gotReply, err := client.UnwrapServerToClient(wrappedReply)
	if err != nil || !bytes.Equal(gotReply, serverReply) {
		t.Fatalf("server unwrap = %q, %v", gotReply, err)
	}
	if client.outbound.seq != 2 || client.inbound.seq != 1 || server.outbound.seq != 1 || server.inbound.seq != 2 {
		t.Fatalf("directional sequence counters client=(%d,%d) server=(%d,%d)", client.outbound.seq, client.inbound.seq, server.outbound.seq, server.inbound.seq)
	}
}

func TestNTLMSSPSecurityContextSignatureMatchesIndependentHMAC(t *testing.T) {
	client, _ := ntlmSSPSecurityContexts(t)
	plaintext := []byte("independent signature input")
	wrapped, err := client.WrapClientToServer(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	seq := make([]byte, 4)
	binary.LittleEndian.PutUint32(seq, 0)
	mac := hmac.New(md5.New, client.outbound.signKey[:])
	_, _ = mac.Write(seq)
	_, _ = mac.Write(plaintext)
	want := mac.Sum(nil)
	if !hmac.Equal(wrapped[4:12], want[:8]) {
		t.Fatalf("signature checksum = %x, want %x", wrapped[4:12], want[:8])
	}
	if got := binary.LittleEndian.Uint32(wrapped[12:16]); got != 0 {
		t.Fatalf("sequence = %d, want 0", got)
	}
}

func TestNTLMSSPSecurityContextRejectsTamperingAndPoisonsDirection(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	wrapped, err := client.WrapClientToServer([]byte("public key hash"))
	if err != nil {
		t.Fatal(err)
	}
	tampered := append([]byte(nil), wrapped...)
	tampered[len(tampered)-1] ^= 0x80
	if plaintext, err := server.inbound.unwrap(tampered); !errors.Is(err, ErrNTLMSSPSecurity) || plaintext != nil {
		t.Fatalf("tampered unwrap = %x, %v", plaintext, err)
	}
	if _, err := server.inbound.unwrap(wrapped); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("direction after tampering = %v, want poisoned context refusal", err)
	}
}

func TestNTLMSSPSecurityContextRejectsReplayAndOutOfOrderMessages(t *testing.T) {
	t.Run("replay", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		wrapped, err := client.WrapClientToServer([]byte("message"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.inbound.unwrap(wrapped); err != nil {
			t.Fatal(err)
		}
		if _, err := server.inbound.unwrap(wrapped); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("replayed message error = %v", err)
		}
	})
	t.Run("out of order", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		first, err := client.WrapClientToServer([]byte("first"))
		if err != nil {
			t.Fatal(err)
		}
		second, err := client.WrapClientToServer([]byte("second"))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := server.inbound.unwrap(second); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("out-of-order message error = %v", err)
		}
		if _, err := server.inbound.unwrap(first); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("direction after sequence failure = %v", err)
		}
	})
}

func TestNTLMSSPSecurityContextRequiresStrictNegotiatedProfile(t *testing.T) {
	var sessionKey [16]byte
	sessionKey[0] = 1
	for _, flags := range []uint32{
		ntlmSSPNegotiateFlags &^ ntlmSSPNegotiateSign,
		ntlmSSPNegotiateFlags &^ ntlmSSPNegotiateSeal,
		ntlmSSPNegotiateFlags &^ ntlmSSPNegotiate128,
		ntlmSSPNegotiateFlags | ntlmSSPNegotiateKeyExchange,
	} {
		if _, err := newNTLMSSPSecurityContext(sessionKey, flags, true); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("flags %#08x error = %v", flags, err)
		}
	}
	if _, err := newNTLMSSPSecurityContext([16]byte{}, ntlmSSPNegotiateFlags, true); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("zero session key error = %v", err)
	}
}

func TestNTLMSSPSecurityContextRejectsInvalidMessagesAndClosedContext(t *testing.T) {
	client, _ := ntlmSSPSecurityContexts(t)
	if _, err := client.UnwrapServerToClient(make([]byte, 15)); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("short message error = %v", err)
	}
	client.Close()
	if _, err := client.WrapClientToServer([]byte("after close")); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("wrap after close error = %v", err)
	}
	if _, err := client.UnwrapServerToClient(make([]byte, 16)); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("unwrap after close error = %v", err)
	}
}

func TestNTLMSSPDirectionalKeyDerivationUsesDistinctNullTerminatedMagic(t *testing.T) {
	var sessionKey [16]byte
	for i := range sessionKey {
		sessionKey[i] = byte(i + 1)
	}
	cases := []struct {
		name  string
		magic string
	}{
		{"client signing", "session key to client-to-server signing key magic constant\x00"},
		{"server signing", "session key to server-to-client signing key magic constant\x00"},
		{"client sealing", "session key to client-to-server sealing key magic constant\x00"},
		{"server sealing", "session key to server-to-client sealing key magic constant\x00"},
	}
	seen := make(map[[16]byte]bool)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			hash := md5.New()
			_, _ = hash.Write(sessionKey[:])
			_, _ = hash.Write([]byte(tc.magic))
			var want [16]byte
			copy(want[:], hash.Sum(nil))
			got := ntlmSSPDeriveSessionKey(sessionKey, tc.magic)
			if got != want {
				t.Fatalf("derived key = %x, want %x", got, want)
			}
			if seen[got] {
				t.Fatalf("directional key %x was reused", got)
			}
			seen[got] = true
		})
	}
}

func TestParseNTLMSSPChallengeRequiresSigningSealingAnd128BitFlags(t *testing.T) {
	for _, flag := range []uint32{ntlmSSPNegotiateSign, ntlmSSPNegotiateSeal, ntlmSSPNegotiate128} {
		data := ntlmSSPTestChallenge(uint32(ntlmSSPNegotiateFlags)&^flag, ntlmSSPTestTargetInfo(t))
		if _, err := ParseNTLMSSPChallenge(data, uint32(ntlmSSPNegotiateFlags)); !errors.Is(err, ErrNTLMSSPMessage) {
			t.Fatalf("challenge without flag %#x error = %v", flag, err)
		}
	}
}

func TestNewNTLMSSPClientSecurityContextRequiresParsedChallenge(t *testing.T) {
	response := NTLMv2Response{
		NTProof:        [16]byte{1},
		NTResponse:     append([]byte{1}, make([]byte, 51)...),
		SessionBaseKey: [16]byte{2},
	}
	if _, err := NewNTLMSSPClientSecurityContext(response, NTLMSSPChallenge{Flags: uint32(ntlmSSPNegotiateFlags)}); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("unparsed challenge error = %v", err)
	}
}

func TestNTLMSSPProtectionMatchesMSNLMPGSSWrapVectorWithoutKeyExchange(t *testing.T) {
	signBytes, err := hex.DecodeString("4788dc861b4782f35d43fd98fe1a2d39")
	if err != nil {
		t.Fatal(err)
	}
	sealBytes, err := hex.DecodeString("59f600973cc4960a25480a7c196e4c58")
	if err != nil {
		t.Fatal(err)
	}
	var signKey, sealKey [16]byte
	copy(signKey[:], signBytes)
	copy(sealKey[:], sealBytes)
	clear(signBytes)
	clear(sealBytes)

	plaintext, err := hex.DecodeString("50006c00610069006e007400650078007400")
	if err != nil {
		t.Fatal(err)
	}
	want, err := hex.DecodeString("0100000070352851f25643090000000054e50165bf1936dc996020c1811b0f06fb5f")
	if err != nil {
		t.Fatal(err)
	}
	protection, err := newNTLMSSPProtection(signKey, sealKey)
	if err != nil {
		t.Fatal(err)
	}
	defer protection.close()
	got, err := protection.wrap(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("GSS_Wrap output = %x, want MS-NLMP vector %x", got, want)
	}

	receiver, err := newNTLMSSPProtection(signKey, sealKey)
	if err != nil {
		t.Fatal(err)
	}
	defer receiver.close()
	unwrapped, err := receiver.unwrap(got)
	if err != nil || !bytes.Equal(unwrapped, plaintext) {
		t.Fatalf("GSS_Unwrap output = %x, %v", unwrapped, err)
	}
}

func TestNewNTLMSSPClientSecurityContextBindsResponseToChallenge(t *testing.T) {
	targetInfo := ntlmSSPTestTargetInfo(t)
	flags := ntlmSSPNegotiateFlags
	challengeBytes := ntlmSSPTestChallenge(flags, targetInfo)
	challenge, err := ParseNTLMSSPChallenge(challengeBytes, flags)
	if err != nil {
		t.Fatal(err)
	}
	response := ntlmSSPTestResponse(t, targetInfo)
	defer response.Purge()

	t.Run("different server challenge", func(t *testing.T) {
		otherBytes := append([]byte(nil), challengeBytes...)
		otherBytes[24] ^= 0x80
		other, err := ParseNTLMSSPChallenge(otherBytes, flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewNTLMSSPClientSecurityContext(response, other); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("mismatched server challenge error = %v", err)
		}
	})
	t.Run("different target info", func(t *testing.T) {
		otherInfo := append([]byte(nil), targetInfo...)
		otherInfo[12] ^= 0x02
		otherBytes := ntlmSSPTestChallenge(flags, otherInfo)
		other, err := ParseNTLMSSPChallenge(otherBytes, flags)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := NewNTLMSSPClientSecurityContext(response, other); !errors.Is(err, ErrNTLMSSPSecurity) {
			t.Fatalf("mismatched target info error = %v", err)
		}
	})
	if _, err := NewNTLMSSPClientSecurityContext(response, challenge); err != nil {
		t.Fatalf("matching challenge rejected: %v", err)
	}
}

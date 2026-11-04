package rdp

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func TestParseNTLMv2AVPairs(t *testing.T) {
	// MS-NLMP §4.2.4 target information: Domain, Server, EOL.
	encoded, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	pairs, err := ParseNTLMv2AVPairs(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 2 || pairs[0].ID != 2 || pairs[1].ID != 1 {
		t.Fatalf("unexpected AV_PAIRs: %#v", pairs)
	}
	if got := string(pairs[0].Value); !bytes.Equal(pairs[0].Value, []byte{0x44, 0, 0x6f, 0, 0x6d, 0, 0x61, 0, 0x69, 0, 0x6e, 0}) {
		t.Fatalf("unexpected domain AV value %x (%q)", pairs[0].Value, got)
	}
}

func TestParseNTLMv2AVPairsRejectsMalformedInput(t *testing.T) {
	valid, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	duplicate := append(append([]byte(nil), valid[:len(valid)-4]...), valid[:len(valid)-4]...)
	duplicate = append(duplicate, 0, 0, 0, 0)
	missingEOL := valid[:len(valid)-4]
	trailing := append(append([]byte(nil), valid...), 0)
	badLength := []byte{6, 0, 3, 0, 0, 0, 0}
	badUnicode := []byte{1, 0, 2, 0, 0x00, 0xd8, 0, 0, 0, 0}
	badTimestamp := []byte{7, 0, 7, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	cases := map[string][]byte{
		"duplicate": duplicate, "missing EOL": missingEOL, "trailing": trailing,
		"flags length": badLength, "invalid UTF-16": badUnicode, "timestamp length": badTimestamp,
		"empty": nil, "oversized": bytes.Repeat([]byte{0}, maxNTLMv2TargetInfo+1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseNTLMv2AVPairs(input); !errors.Is(err, ErrNTLMv2AVPair) {
				t.Fatalf("ParseNTLMv2AVPairs() error = %v, want %v", err, ErrNTLMv2AVPair)
			}
		})
	}
}

func TestParseNTLMv2AVPairsAcceptsEmptyAndUnknownAttributes(t *testing.T) {
	if pairs, err := ParseNTLMv2AVPairs([]byte{0, 0, 0, 0}); err != nil || len(pairs) != 0 {
		t.Fatalf("empty AV list = %#v, %v", pairs, err)
	}
	encoded := []byte{0x34, 0x12, 1, 0, 0xaa, 0, 0, 0, 0}
	pairs, err := ParseNTLMv2AVPairs(encoded)
	if err != nil || len(pairs) != 1 || pairs[0].ID != 0x1234 || !bytes.Equal(pairs[0].Value, []byte{0xaa}) {
		t.Fatalf("unknown AV_PAIR not preserved: %#v, %v", pairs, err)
	}
}

func TestParseNTLMv2AVPairsEnforcesPairCount(t *testing.T) {
	encoded := make([]byte, 0, (maxNTLMv2AVPairs+1)*4+4)
	for id := 0x0100; id < 0x0100+maxNTLMv2AVPairs+1; id++ {
		encoded = append(encoded, byte(id), byte(id>>8), 0, 0)
	}
	encoded = append(encoded, 0, 0, 0, 0)
	if _, err := ParseNTLMv2AVPairs(encoded); !errors.Is(err, ErrNTLMv2AVPair) {
		t.Fatalf("too many AV_PAIRs error = %v, want ErrNTLMv2AVPair", err)
	}
}

func TestComputeNTLMv2ResponseMicrosoftVector(t *testing.T) {
	password := []byte("Password")
	defer clear(password)
	serverChallenge := mustHex8(t, "0123456789abcdef")
	clientChallenge := mustHex8(t, "aaaaaaaaaaaaaaaa")
	timestamp := mustHex8(t, "0000000000000000")
	targetInfo, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")

	got, err := ComputeNTLMv2Response("User", "Domain", password, serverChallenge, clientChallenge, timestamp, targetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Purge()
	wantNT, _ := hex.DecodeString("68cd0ab851e51c96aabc927bebef6a1c01010000000000000000000000000000aaaaaaaaaaaaaaaa0000000002000c0044006f006d00610069006e0001000c005300650072007600650072000000000000000000")
	wantLM, _ := hex.DecodeString("86c35097ac9cec102554764a57cccc19aaaaaaaaaaaaaaaa")
	wantSessionKey, _ := hex.DecodeString("8de40ccadbc14a82f15cb0ad0de95ca3")
	if !bytes.Equal(got.NTResponse, wantNT) {
		t.Fatalf("NT response = %x, want %x", got.NTResponse, wantNT)
	}
	if !bytes.Equal(got.LMResponse[:], wantLM) {
		t.Fatalf("LMv2 response = %x, want %x", got.LMResponse, wantLM)
	}
	if !bytes.Equal(got.SessionBaseKey[:], wantSessionKey) {
		t.Fatalf("session base key = %x, want %x", got.SessionBaseKey, wantSessionKey)
	}
	if !bytes.Equal(got.NTProof[:], wantNT[:16]) {
		t.Fatalf("NT proof = %x, want %x", got.NTProof, wantNT[:16])
	}
}

func TestComputeNTLMv2ResponseUsesServerTimestampAndZeroLMResponse(t *testing.T) {
	password := []byte("Password")
	defer clear(password)
	serverChallenge := mustHex8(t, "0123456789abcdef")
	clientChallenge := mustHex8(t, "aaaaaaaaaaaaaaaa")
	clientTimestamp := mustHex8(t, "0000000000000000")
	serverTimestamp := mustHex8(t, "8877665544332211")
	baseTargetInfo, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	targetInfo := append([]byte{ntlmAvTimestamp, 0, 8, 0}, serverTimestamp[:]...)
	targetInfo = append(targetInfo, baseTargetInfo...)

	got, err := ComputeNTLMv2Response("User", "Domain", password, serverChallenge, clientChallenge, clientTimestamp, targetInfo)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Purge()
	if !bytes.Equal(got.NTResponse[16+8:16+16], serverTimestamp[:]) {
		t.Fatalf("NTLMv2 blob timestamp = %x, want server FILETIME %x", got.NTResponse[24:32], serverTimestamp)
	}
	if got.LMResponse != ([24]byte{}) {
		t.Fatalf("LMChallengeResponse = %x, want Z(24)", got.LMResponse)
	}
	if allZero(got.NTProof[:]) || allZero(got.SessionBaseKey[:]) {
		t.Fatal("server timestamp produced empty NT proof or session key")
	}
}

func TestComputeNTLMv2ResponseRejectsInvalidInputs(t *testing.T) {
	password := []byte("Password")
	defer clear(password)
	serverChallenge := mustHex8(t, "0123456789abcdef")
	clientChallenge := mustHex8(t, "aaaaaaaaaaaaaaaa")
	timestamp := mustHex8(t, "0000000000000000")
	targetInfo, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	cases := []struct {
		name, user, domain string
		password           []byte
		server, client     [8]byte
		timestamp          [8]byte
		info               []byte
	}{
		{name: "empty username", user: "", domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: targetInfo},
		{name: "empty password", user: "User", domain: "Domain", password: nil, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: targetInfo},
		{name: "invalid UTF-8 username", user: string([]byte{0xff}), domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: targetInfo},
		{name: "NUL in domain", user: "User", domain: "Do\x00main", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: targetInfo},
		{name: "unsupported MIC flag bits", user: "User", domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: append([]byte{6, 0, 4, 0, 6, 0, 0, 0}, targetInfo...)},
		{name: "target name requires binding", user: "User", domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: append([]byte{9, 0, 6, 0, 0x52, 0, 0x44, 0, 0x50, 0}, targetInfo...)},
		{name: "channel binding requires TLS binding", user: "User", domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: append([]byte{10, 0, 16, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, targetInfo...)},
		{name: "invalid target info", user: "User", domain: "Domain", password: password, server: serverChallenge, client: clientChallenge, timestamp: timestamp, info: []byte{1, 0, 0, 0}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ComputeNTLMv2Response(tc.user, tc.domain, tc.password, tc.server, tc.client, tc.timestamp, tc.info); !errors.Is(err, ErrNTLMv2Input) && !errors.Is(err, ErrNTLMv2AVPair) {
				t.Fatalf("ComputeNTLMv2Response() error = %v, want input/AV_PAIR error", err)
			}
		})
	}
}

func TestComputeNTLMv2ResponseUsernameCaseInsensitive(t *testing.T) {
	password := []byte("Password")
	defer clear(password)
	server := mustHex8(t, "0123456789abcdef")
	client := mustHex8(t, "aaaaaaaaaaaaaaaa")
	timestamp := mustHex8(t, "0000000000000000")
	target, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	first, err := ComputeNTLMv2Response("User", "Domain", password, server, client, timestamp, target)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Purge()
	second, err := ComputeNTLMv2Response("USER", "Domain", password, server, client, timestamp, target)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Purge()
	if first.NTProof != second.NTProof {
		t.Fatalf("username case changed NTProof: %x != %x", first.NTProof, second.NTProof)
	}
}

func TestGenerateNTLMv2ClientChallenge(t *testing.T) {
	first, err := GenerateNTLMv2ClientChallenge()
	if err != nil {
		t.Fatal(err)
	}
	second, err := GenerateNTLMv2ClientChallenge()
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("independent client challenges unexpectedly matched")
	}
}

func TestNTLMv2ResponsePurge(t *testing.T) {
	response := NTLMv2Response{
		NTProof: [16]byte{1}, NTResponse: []byte{1, 2},
		LMResponse: [24]byte{1}, SessionBaseKey: [16]byte{1},
	}
	response.Purge()
	if response.NTProof != ([16]byte{}) || response.LMResponse != ([24]byte{}) || response.SessionBaseKey != ([16]byte{}) || !bytes.Equal(response.NTResponse, []byte{0, 0}) {
		t.Fatal("Purge did not clear NTLMv2 response material")
	}
}

func FuzzParseNTLMv2AVPairs(f *testing.F) {
	valid, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	f.Add(valid)
	f.Add([]byte{0, 0, 0, 0})
	f.Add([]byte{1, 0, 1, 0, 0, 0, 0, 0})
	f.Fuzz(func(t *testing.T, data []byte) {
		pairs, err := ParseNTLMv2AVPairs(data)
		if err == nil {
			if len(pairs) > maxNTLMv2AVPairs {
				t.Fatalf("parser returned %d pairs", len(pairs))
			}
			for _, pair := range pairs {
				if pair.ID == ntlmAvEOL || len(pair.Value) > maxNTLMv2TargetInfo {
					t.Fatalf("parser returned invalid pair %#v", pair)
				}
			}
		}
	})
}

func mustHex8(t *testing.T, value string) (out [8]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		t.Fatalf("invalid test vector %q", value)
	}
	copy(out[:], decoded)
	return out
}

func mustHex16(t *testing.T, value string) (out [16]byte) {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != len(out) {
		t.Fatalf("invalid test vector %q", value)
	}
	copy(out[:], decoded)
	return out
}

func TestNTLMv2ServerTargetInfoForProof_PreservesServerBytesWithoutClientMutation(t *testing.T) {
	base, _ := hex.DecodeString("02000c0044006f006d00610069006e0001000c0053006500720076006500720000000000")
	got, err := NTLMv2ServerTargetInfoForProof(base)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.Equal(got, base) {
		t.Fatalf("TargetInfo changed before NTProof: got %x want %x", got, base)
	}
	malformed := append([]byte(nil), base...)
	malformed[len(malformed)-1] = 1
	if _, err := NTLMv2ServerTargetInfoForProof(malformed); !errors.Is(err, ErrNTLMv2AVPair) {
		t.Fatalf("malformed TargetInfo error = %v", err)
	}
}

func TestNTLMv2TargetInfoWithClientBindings_AppendsWithoutChangingServerPrefix(t *testing.T) {
	serverInfo := ntlmSSPTestTargetInfo(t)
	name, err := NTLMv2TargetName("rdp.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(name)
	bindings := NTLMv2ClientBindings{TargetName: name, ChannelBindings: mustHex16(t, "00112233445566778899aabbccddeeff")}
	got, err := NTLMv2TargetInfoWithClientBindings(serverInfo, bindings)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	if !bytes.HasPrefix(got, serverInfo[:len(serverInfo)-4]) {
		t.Fatalf("server AV_PAIR prefix changed: %x", got)
	}
	pairs, err := ParseNTLMv2AVPairs(got)
	if err != nil {
		t.Fatal(err)
	}
	if len(pairs) != 5 || pairs[3].ID != ntlmAvChannelBindings || !bytes.Equal(pairs[3].Value, bindings.ChannelBindings[:]) || pairs[4].ID != ntlmAvTargetName || !bytes.Equal(pairs[4].Value, name) {
		t.Fatalf("client binding AV_PAIRs = %#v", pairs)
	}
	bad := bindings
	bad.ChannelBindings = [16]byte{}
	if _, err := NTLMv2TargetInfoWithClientBindings(serverInfo, bad); !errors.Is(err, ErrNTLMv2Input) {
		t.Fatalf("zero channel binding error = %v", err)
	}
	bad = bindings
	bad.TargetName = mustUTF16LE(t, "TERMSRV/rdp.example.test\x00.evil")
	if _, err := NTLMv2TargetInfoWithClientBindings(serverInfo, bad); !errors.Is(err, ErrNTLMv2Input) {
		t.Fatalf("NUL-containing target name error = %v", err)
	}
	bad.TargetName = mustUTF16LE(t, "HTTP/rdp.example.test")
	if _, err := NTLMv2TargetInfoWithClientBindings(serverInfo, bad); !errors.Is(err, ErrNTLMv2Input) {
		t.Fatalf("non-RDP SPN error = %v", err)
	}
}

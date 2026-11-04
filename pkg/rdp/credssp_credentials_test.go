package rdp

import (
	"bytes"
	"errors"
	"testing"
)

func TestMarshalCredSSPPasswordCredentialsUsesUTF16LEAndPasswordCredentialType(t *testing.T) {
	const password = "Pässwörd🔐"
	encoded, err := marshalCredSSPPasswordCredentials("Dömäin", "Usér", []byte(password))
	if err != nil {
		t.Fatalf("marshal credentials: %v", err)
	}
	defer clear(encoded)
	if bytes.Contains(encoded, []byte(password)) {
		t.Fatal("DER TSCredentials unexpectedly contains the UTF-8 password representation")
	}
	domain, username, gotPassword, err := parseCredSSPPasswordCredentialsForTest(encoded)
	if err != nil {
		t.Fatalf("parse TSCredentials: %v", err)
	}
	if domain != "Dömäin" || username != "Usér" || gotPassword != password {
		t.Fatalf("decoded credentials = (%q, %q, %q)", domain, username, gotPassword)
	}

	emptyDomain, err := marshalCredSSPPasswordCredentials("", "User", []byte("Password"))
	if err != nil {
		t.Fatalf("empty account domain should be representable: %v", err)
	}
	defer clear(emptyDomain)
	gotDomain, gotUser, gotSecret, err := parseCredSSPPasswordCredentialsForTest(emptyDomain)
	if err != nil || gotDomain != "" || gotUser != "User" || gotSecret != "Password" {
		t.Fatalf("empty-domain credentials = (%q, %q, %q), %v", gotDomain, gotUser, gotSecret, err)
	}
}

func TestMarshalCredSSPPasswordCredentialsRejectsInvalidAndOversizedInputs(t *testing.T) {
	for name, input := range map[string]struct {
		domain, username string
		password         []byte
	}{
		"empty username":        {domain: "DOMAIN", password: []byte("secret")},
		"empty password":        {username: "user"},
		"invalid domain utf8":   {domain: string([]byte{0xff}), username: "user", password: []byte("secret")},
		"invalid username utf8": {username: string([]byte{0xff}), password: []byte("secret")},
		"invalid password utf8": {username: "user", password: []byte{0xff}},
		"domain contains NUL":   {domain: "DO\x00MAIN", username: "user", password: []byte("secret")},
		"username contains NUL": {username: "us\x00er", password: []byte("secret")},
		"oversized domain":      {domain: string(bytes.Repeat([]byte("d"), maxCredSSPDomainBytes+1)), username: "user", password: []byte("secret")},
		"oversized username":    {username: string(bytes.Repeat([]byte("u"), maxCredSSPUsernameBytes+1)), password: []byte("secret")},
		"oversized password":    {username: "user", password: bytes.Repeat([]byte("p"), maxCredSSPPasswordBytes+1)},
	} {
		t.Run(name, func(t *testing.T) {
			if got, err := marshalCredSSPPasswordCredentials(input.domain, input.username, input.password); !errors.Is(err, ErrCredSSPCredentials) || got != nil {
				clear(got)
				t.Fatalf("marshal = %x, %v; want nil, ErrCredSSPCredentials", got, err)
			}
		})
	}
}

func TestTSRequestAuthInfoShapeIsStrict(t *testing.T) {
	valid, err := MarshalTSRequest(TSRequest{Version: 6, AuthInfo: []byte("sealed")})
	if err != nil {
		t.Fatal(err)
	}
	if !tsRequestContainsOnlyVersionAndAuthInfo(valid) {
		t.Fatal("version + authInfo request rejected")
	}
	for name, request := range map[string]TSRequest{
		"negoTokens": {Version: 6, NegoTokens: [][]byte{{1}}, AuthInfo: []byte("sealed")},
		"pubKeyAuth": {Version: 6, PubKeyAuth: []byte("binding"), AuthInfo: []byte("sealed")},
		"errorCode":  {Version: 6, ErrorCode: ptrUint32(1), AuthInfo: []byte("sealed")},
		"nonce":      {Version: 6, ClientNonce: bytes.Repeat([]byte{1}, 32), AuthInfo: []byte("sealed")},
	} {
		t.Run(name, func(t *testing.T) {
			encoded, err := MarshalTSRequest(request)
			if err != nil {
				t.Fatal(err)
			}
			if tsRequestContainsOnlyVersionAndAuthInfo(encoded) {
				t.Fatal("unexpected TSRequest field was accepted")
			}
		})
	}
}

func ptrUint32(value uint32) *uint32 { return &value }

func TestCredSSPAuthInfoTamperingPoisonsTheNTLMSequence(t *testing.T) {
	var exported [16]byte
	for i := range exported {
		exported[i] = byte(i + 1)
	}
	client, err := newNTLMSSPSecurityContext(exported, ntlmSSPNegotiateFlags, true)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	server, err := newNTLMSSPSecurityContext(exported, ntlmSSPNegotiateFlags, false)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	binding, err := client.WrapClientToServer([]byte("validated pubKeyAuth"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := server.inbound.unwrap(binding); err != nil {
		t.Fatalf("server binding unwrap: %v", err)
	}
	credentials, err := marshalCredSSPPasswordCredentials("DOMAIN", "User", []byte("Password"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	sealed, err := client.WrapClientToServer(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(sealed)
	sealed[4] ^= 0x80 // alter the message signature after sealing
	if _, err := server.inbound.unwrap(sealed); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("tampered authInfo unwrap error = %v", err)
	}
	validNext, err := client.WrapClientToServer(credentials)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(validNext)
	if _, err := server.inbound.unwrap(validNext); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("poisoned inbound sequence accepted a later authInfo: %v", err)
	}
}

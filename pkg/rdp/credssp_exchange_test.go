package rdp

import (
	"bytes"
	"errors"
	"testing"
)

func credSSPTestBinding() CredSSPPublicKeyBinding {
	var binding CredSSPPublicKeyBinding
	for i := range binding.ClientNonce {
		binding.ClientNonce[i] = byte(i + 1)
	}
	for i := range binding.ClientToServerHash {
		binding.ClientToServerHash[i] = byte(0x40 + i)
		binding.ServerToClientHash[i] = byte(0x80 + i)
	}
	binding.valid = true
	return binding
}

func credSSPTestServerHash() []byte {
	binding := credSSPTestBinding()
	return append([]byte(nil), binding.ServerToClientHash[:]...)
}

func TestCredSSPClientBindingRequestAndServerResponse(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	binding := credSSPTestBinding()
	lastToken := []byte{0xa1, 0x03, 0x02, 0x01, 0x00}

	request, err := NewCredSSPClientBindingRequest(6, lastToken, binding, client)
	if err != nil {
		t.Fatal(err)
	}
	if request.Version != 6 || len(request.NegoTokens) != 1 ||
		!bytes.Equal(request.NegoTokens[0], lastToken) ||
		!bytes.Equal(request.ClientNonce, binding.ClientNonce[:]) ||
		len(request.PubKeyAuth) != ntlmSSPMessageSignatureSize+len(binding.ClientToServerHash) {
		t.Fatalf("unexpected client binding TSRequest: %#v", request)
	}
	if bytes.Contains(request.PubKeyAuth, binding.ClientToServerHash[:]) {
		t.Fatal("pubKeyAuth contains the unsealed client hash")
	}

	encoded, err := MarshalTSRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseTSRequest(encoded)
	if err != nil || parsed.Version != 6 || len(parsed.NegoTokens) != 1 {
		t.Fatalf("parse client binding request = %#v, %v", parsed, err)
	}
	clientHash, err := server.inbound.unwrap(parsed.PubKeyAuth)
	if err != nil || !bytes.Equal(clientHash, binding.ClientToServerHash[:]) {
		t.Fatalf("server unsealed client hash = %x, %v", clientHash, err)
	}

	serverPubKeyAuth, err := server.outbound.wrap(binding.ServerToClientHash[:])
	if err != nil {
		t.Fatal(err)
	}
	serverResponse, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: serverPubKeyAuth})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCredSSPServerBindingResponse(serverResponse, 6, binding, client); err != nil {
		t.Fatalf("verify server binding response: %v", err)
	}
}

func TestCredSSPClientBindingRequestRejectsInvalidInputs(t *testing.T) {
	client, _ := ntlmSSPSecurityContexts(t)
	binding := credSSPTestBinding()
	cases := []struct {
		name    string
		version uint32
		token   []byte
		binding CredSSPPublicKeyBinding
	}{
		{"legacy version", 4, []byte{1}, binding},
		{"unsupported version", 7, []byte{1}, binding},
		{"empty final token", 6, nil, binding},
		{"oversized final token", 6, bytes.Repeat([]byte{1}, maxCredSSPToken+1), binding},
		{"zero binding", 6, []byte{1}, CredSSPPublicKeyBinding{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := NewCredSSPClientBindingRequest(tc.version, tc.token, tc.binding, client); !errors.Is(err, ErrCredSSPBindingExchange) {
				t.Fatalf("error = %v, want ErrCredSSPBindingExchange", err)
			}
		})
	}
	if client.outbound.seq != 0 {
		t.Fatalf("invalid input consumed outbound sequence %d", client.outbound.seq)
	}
}

func TestCredSSPServerBindingResponseRequiresExactShape(t *testing.T) {
	cases := []struct {
		name string
		make func([]byte) TSRequest
	}{
		{"negoTokens", func(sealed []byte) TSRequest {
			return TSRequest{Version: 6, NegoTokens: [][]byte{{1}}, PubKeyAuth: sealed}
		}},
		{"authInfo", func(sealed []byte) TSRequest { return TSRequest{Version: 6, AuthInfo: []byte{1}, PubKeyAuth: sealed} }},
		{"errorCode", func(sealed []byte) TSRequest {
			code := uint32(1)
			return TSRequest{Version: 6, ErrorCode: &code, PubKeyAuth: sealed}
		}},
		{"clientNonce", func(sealed []byte) TSRequest {
			return TSRequest{Version: 6, ClientNonce: bytes.Repeat([]byte{1}, 32), PubKeyAuth: sealed}
		}},
		{"empty pubKeyAuth", func([]byte) TSRequest { return TSRequest{Version: 6, PubKeyAuth: []byte{}} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			client, server := ntlmSSPSecurityContexts(t)
			sealed, err := server.outbound.wrap(credSSPTestServerHash())
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := MarshalTSRequest(tc.make(sealed))
			if err != nil {
				t.Fatal(err)
			}
			if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); !errors.Is(err, ErrCredSSPBindingExchange) {
				t.Fatalf("error = %v, want ErrCredSSPBindingExchange", err)
			}
			if _, err := client.WrapClientToServer([]byte("must be closed")); !errors.Is(err, ErrNTLMSSPSecurity) {
				t.Fatalf("context remained usable after invalid response: %v", err)
			}
		})
	}
}

func TestCredSSPServerBindingResponseRejectsVersionMismatchAndTampering(t *testing.T) {
	t.Run("version mismatch", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		sealed, err := server.outbound.wrap(credSSPTestServerHash())
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := MarshalTSRequest(TSRequest{Version: 5, PubKeyAuth: sealed})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); !errors.Is(err, ErrCredSSPBindingExchange) {
			t.Fatalf("version mismatch error = %v", err)
		}
	})
	t.Run("wrong server hash", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		wrong := bytes.Repeat([]byte{0xee}, 32)
		sealed, err := server.outbound.wrap(wrong)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: sealed})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); !errors.Is(err, ErrCredSSPBindingExchange) {
			t.Fatalf("wrong hash error = %v", err)
		}
	})
	t.Run("tampered signature", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		sealed, err := server.outbound.wrap(credSSPTestServerHash())
		if err != nil {
			t.Fatal(err)
		}
		sealed[4] ^= 0x80
		encoded, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: sealed})
		if err != nil {
			t.Fatal(err)
		}
		if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); !errors.Is(err, ErrCredSSPBindingExchange) {
			t.Fatalf("tampered response error = %v", err)
		}
	})
}

func TestCredSSPServerBindingResponseCannotBeReplayed(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	sealed, err := server.outbound.wrap(credSSPTestServerHash())
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: sealed})
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); err != nil {
		t.Fatal(err)
	}
	if err := VerifyCredSSPServerBindingResponse(encoded, 6, credSSPTestBinding(), client); !errors.Is(err, ErrCredSSPBindingExchange) {
		t.Fatalf("replayed response error = %v", err)
	}
}

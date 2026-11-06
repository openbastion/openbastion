package rdp

import (
	"bytes"
	"errors"
	"testing"
)

// conn is what the server said, and records what this client wrote.
type micTestConn struct {
	bytes.Buffer
	written bytes.Buffer
}

func (c *micTestConn) Write(p []byte) (int, error) { return c.written.Write(p) }

func micTestAnswer(t *testing.T, request TSRequest) *micTestConn {
	t.Helper()
	encoded, err := MarshalTSRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	conn := &micTestConn{}
	conn.Buffer.Write(encoded)
	return conn
}

func micTestCompletion(mic []byte) []byte {
	fields := derWrap(0xa0, derWrap(0x0a, []byte{spnegoStateAcceptCompleted}))
	if len(mic) != 0 {
		fields = append(fields, derWrap(0xa3, derWrap(0x04, mic))...)
	}
	return derWrap(0xa1, derWrap(0x30, fields))
}

func TestMechListMIC_EachDirectionProvesTheListItself(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	types, err := spnegoNTLMMechTypes()
	if err != nil {
		t.Fatal(err)
	}
	fromServer, err := server.SignMechListMIC(types)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.VerifyMechListMIC(types, fromServer); err != nil {
		t.Fatalf("the server's MIC: %v", err)
	}
	fromClient, err := client.SignMechListMIC(types)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(fromClient, fromServer) {
		t.Fatal("both directions sign alike: a MIC could be reflected")
	}
	if err := client.VerifyMechListMIC(types, fromClient); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("this client accepted its own MIC back: %v", err)
	}
	if err := client.VerifyMechListMIC(append([]byte{0x30}, types...), fromServer); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("a MIC over another list: %v", err)
	}
	tampered := append([]byte(nil), fromServer...)
	tampered[5] ^= 1
	if err := client.VerifyMechListMIC(types, tampered); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("a tampered MIC: %v", err)
	}
	if err := client.VerifyMechListMIC(types, fromServer[:15]); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("a short MIC: %v", err)
	}
}

// The exchange leaves the streams where they were and counts one message each way.
func TestMechListMIC_TheConfidentialityStreamsAreAtTheirStartAtSequenceOne(t *testing.T) {
	client, server := ntlmSSPSecurityContexts(t)
	types, _ := spnegoNTLMMechTypes()
	if _, err := client.SignMechListMIC(types); err != nil {
		t.Fatal(err)
	}
	for _, side := range []*NTLMSSPClientSecurityContext{client, server} {
		if err := side.mechListMICExchanged(); err != nil {
			t.Fatal(err)
		}
	}
	sealed, err := client.WrapClientToServer([]byte("pubKeyAuth"))
	if err != nil {
		t.Fatal(err)
	}
	if sealed[12] != 1 {
		t.Fatalf("sequence %d, want 1", sealed[12])
	}
	if got, err := server.UnwrapServerToClient(sealed); err != nil || string(got) != "pubKeyAuth" {
		t.Fatalf("%q, %v", got, err)
	}
	if err := client.mechListMICExchanged(); !errors.Is(err, ErrNTLMSSPSecurity) {
		t.Fatalf("counted twice: %v", err)
	}
}

func TestSPNEGOMICExchange_AServerThatDoesNotFinishItIsRefused(t *testing.T) {
	types, _ := spnegoNTLMMechTypes()
	token := []byte{0xa1, 0x03, 0x30, 0x01, 0x00}
	version := uint32(6)
	valid := func(t *testing.T, server *NTLMSSPClientSecurityContext) []byte {
		mic, err := server.SignMechListMIC(types)
		if err != nil {
			t.Fatal(err)
		}
		return mic
	}
	for name, answer := range map[string]func(t *testing.T, client, server *NTLMSSPClientSecurityContext) TSRequest{
		"no token at all": func(t *testing.T, _, _ *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: version}
		},
		"no MIC": func(t *testing.T, _, _ *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: version, NegoTokens: [][]byte{micTestCompletion(nil)}}
		},
		"a forged MIC": func(t *testing.T, _, _ *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: version, NegoTokens: [][]byte{micTestCompletion(bytes.Repeat([]byte{7}, 16))}}
		},
		"this client's own MIC, reflected": func(t *testing.T, client, _ *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: version, NegoTokens: [][]byte{micTestCompletion(valid(t, client))}}
		},
		"another version": func(t *testing.T, _, server *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: 5, NegoTokens: [][]byte{micTestCompletion(valid(t, server))}}
		},
		"a pubKeyAuth that answers nothing": func(t *testing.T, _, server *NTLMSSPClientSecurityContext) TSRequest {
			return TSRequest{Version: version, NegoTokens: [][]byte{micTestCompletion(valid(t, server))}, PubKeyAuth: bytes.Repeat([]byte{1}, 48)}
		},
	} {
		t.Run(name, func(t *testing.T) {
			client, server := ntlmSSPSecurityContexts(t)
			conn := micTestAnswer(t, answer(t, client, server))
			if err := completeSPNEGOMICExchange(conn, version, token, client, types); err == nil {
				t.Fatal("accepted")
			}
			// Nothing is counted: the session cannot go on to pubKeyAuth as if it had finished.
			if client.outbound.seq != 0 {
				t.Fatalf("sequence %d after a refusal", client.outbound.seq)
			}
		})
	}
	t.Run("a server that finishes it", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		conn := micTestAnswer(t, TSRequest{Version: version, NegoTokens: [][]byte{micTestCompletion(valid(t, server))}})
		if err := completeSPNEGOMICExchange(conn, version, token, client, types); err != nil {
			t.Fatal(err)
		}
		sent, err := ParseTSRequest(conn.written.Bytes())
		if err != nil || sent.PubKeyAuth != nil || sent.ClientNonce != nil || len(sent.NegoTokens) != 1 {
			t.Fatalf("what is sent before the MIC is proved: %+v, %v", sent, err)
		}
		if client.outbound.seq != 1 || client.inbound.seq != 1 {
			t.Fatalf("sequences %d, %d", client.outbound.seq, client.inbound.seq)
		}
	})
}

// What FreeRDP does when both arrive at once: it sends back what it was sent. Taking that for the
// server's proof would authenticate nobody.
func TestCredSSPServerProof_AReflectedPubKeyAuthIsRefused(t *testing.T) {
	client, _ := ntlmSSPSecurityContexts(t)
	binding := credSSPTestBinding()
	types, _ := spnegoNTLMMechTypes()
	sent, err := NewCredSSPClientBindingRequest(6, nil, binding, client)
	if err != nil {
		t.Fatal(err)
	}
	reflected, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: sent.PubKeyAuth})
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyCredSSPServerCompletion(reflected, 6, binding, client, types); !errors.Is(err, ErrCredSSPBindingExchange) {
		t.Fatalf("a reflected pubKeyAuth: %v", err)
	}
}

func TestCredSSPServerProof_ALastTokenIsCheckedLikeAnyOther(t *testing.T) {
	binding := credSSPTestBinding()
	types, _ := spnegoNTLMMechTypes()
	build := func(t *testing.T, server *NTLMSSPClientSecurityContext, token []byte) []byte {
		sealed, err := server.WrapClientToServer(binding.ServerToClientHash[:])
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{token}, PubKeyAuth: sealed})
		if err != nil {
			t.Fatal(err)
		}
		return encoded
	}
	t.Run("its MIC verifies", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		mic, _ := server.SignMechListMIC(types)
		if err := verifyCredSSPServerCompletion(build(t, server, micTestCompletion(mic)), 6, binding, client, types); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("its MIC does not", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		if err := verifyCredSSPServerCompletion(build(t, server, micTestCompletion(bytes.Repeat([]byte{9}, 16))), 6, binding, client, types); !errors.Is(err, ErrCredSSPBindingExchange) {
			t.Fatalf("%v", err)
		}
	})
	t.Run("it reopens the negotiation", func(t *testing.T) {
		client, server := ntlmSSPSecurityContexts(t)
		token := derWrap(0xa1, derWrap(0x30, derWrap(0xa0, derWrap(0x0a, []byte{spnegoStateAcceptIncomplete}))))
		if err := verifyCredSSPServerCompletion(build(t, server, token), 6, binding, client, types); !errors.Is(err, ErrCredSSPBindingExchange) {
			t.Fatalf("%v", err)
		}
	})
}

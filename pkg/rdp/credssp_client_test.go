package rdp

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestMarshalSPNEGONTLMInitAndResponse(t *testing.T) {
	negotiate := MarshalNTLMSSPNegotiate()
	initial, err := MarshalSPNEGONTLMInit(negotiate)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseSPNEGONegTokenInit(initial)
	if err != nil || len(parsed.Mechanisms) != 1 || !parsed.Mechanisms[0].Equal(ntlmOID) || !bytes.Equal(parsed.MechanismToken, negotiate) {
		t.Fatalf("parsed initial token = %#v, %v", parsed, err)
	}

	mechanism := []byte("ntlm-authenticate")
	response, err := MarshalSPNEGONTLMResponse(mechanism)
	if err != nil {
		t.Fatal(err)
	}
	parsedResponse, err := ParseSPNEGONegTokenResp(response)
	if err != nil || parsedResponse.State != 0 || len(parsedResponse.SupportedMech) != 0 || !bytes.Equal(parsedResponse.ResponseToken, mechanism) {
		t.Fatalf("parsed final token = %#v, %v", parsedResponse, err)
	}
	if _, err := MarshalSPNEGONTLMInit(nil); !errors.Is(err, ErrSPNEGOToken) {
		t.Fatalf("empty initial mechanism token error = %v", err)
	}
	if _, err := MarshalSPNEGONTLMResponse(bytes.Repeat([]byte{1}, maxSPNEGOToken+1)); !errors.Is(err, ErrSPNEGOToken) {
		t.Fatalf("oversized final mechanism token error = %v", err)
	}
}

func TestReadTSRequestIsBoundedAndConsumesExactlyOneMessage(t *testing.T) {
	first, err := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{{1, 2, 3}}})
	if err != nil {
		t.Fatal(err)
	}
	second, err := MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: []byte{4, 5, 6}})
	if err != nil {
		t.Fatal(err)
	}
	stream := bytes.NewReader(append(append([]byte(nil), first...), second...))
	gotFirst, err := readTSRequest(stream)
	if err != nil || !bytes.Equal(gotFirst, first) {
		t.Fatalf("first TSRequest = %x, %v", gotFirst, err)
	}
	gotSecond, err := readTSRequest(stream)
	if err != nil || !bytes.Equal(gotSecond, second) || stream.Len() != 0 {
		t.Fatalf("second TSRequest = %x, %v; remaining=%d", gotSecond, err, stream.Len())
	}
	for name, input := range map[string][]byte{
		"empty":            nil,
		"wrong tag":        {0x31, 0x00},
		"indefinite":       {0x30, 0x80, 0, 0},
		"truncated length": {0x30, 0x82, 0x01},
		"oversized body":   {0x30, 0x83, 0x01, 0x00, 0x01},
		"truncated body":   {0x30, 0x03, 0x02, 0x01},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := readTSRequest(bytes.NewReader(input)); !errors.Is(err, ErrCredSSPMessage) {
				t.Fatalf("error = %v, want ErrCredSSPMessage", err)
			}
		})
	}
}

func TestEstablishCredSSPOverPinnedTLS(t *testing.T) {
	certificate, roots, pin := rdpTestCertificate(t)
	serverLeaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	targetInfo := ntlmSSPTestTargetInfo(t)
	serverResult := make(chan error, 1)
	go func() {
		conn, acceptErr := listener.Accept()
		if acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		defer conn.Close()
		if _, acceptErr = readTestTPKT(conn); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		if acceptErr = writeFull(conn, connectionConfirm(protocolHybrid)); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		if acceptErr = tlsConn.Handshake(); acceptErr != nil {
			serverResult <- acceptErr
			return
		}
		initialBytes, readErr := readTSRequest(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		initial, readErr := ParseTSRequest(initialBytes)
		clear(initialBytes)
		if readErr != nil || initial.Version != 6 || len(initial.NegoTokens) != 1 || initial.PubKeyAuth != nil {
			serverResult <- errors.New("invalid initial CredSSP TSRequest")
			return
		}
		initToken, readErr := ParseSPNEGONegTokenInit(initial.NegoTokens[0])
		if readErr != nil || len(initToken.Mechanisms) != 1 || !initToken.Mechanisms[0].Equal(ntlmOID) || !bytes.Equal(initToken.MechanismToken, MarshalNTLMSSPNegotiate()) {
			serverResult <- errors.New("invalid SPNEGO initial token")
			return
		}

		challengeBytes := ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, targetInfo)
		challenge, readErr := ParseNTLMSSPChallenge(challengeBytes, ntlmSSPNegotiateFlags)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		challengeToken := spnegoChallengeForTest(challengeBytes)
		challengeRequest, readErr := MarshalTSRequest(TSRequest{Version: 5, NegoTokens: [][]byte{challengeToken}})
		if readErr != nil || writeFull(tlsConn, challengeRequest) != nil {
			serverResult <- errors.New("could not send NTLM challenge")
			return
		}

		finalBytes, readErr := readTSRequest(tlsConn)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		if bytes.Contains(finalBytes, []byte("Password")) {
			clear(finalBytes)
			serverResult <- errors.New("plaintext password appeared in CredSSP traffic")
			return
		}
		finalRequest, readErr := ParseTSRequest(finalBytes)
		clear(finalBytes)
		if readErr != nil || finalRequest.Version != 5 || len(finalRequest.NegoTokens) != 1 || len(finalRequest.PubKeyAuth) == 0 || len(finalRequest.ClientNonce) != 32 || finalRequest.AuthInfo != nil {
			serverResult <- errors.New("invalid final CredSSP binding request")
			return
		}
		finalSPNEGO, readErr := ParseSPNEGONegTokenResp(finalRequest.NegoTokens[0])
		if readErr != nil || len(finalSPNEGO.ResponseToken) == 0 || finalSPNEGO.State != 0 || len(finalSPNEGO.MechanismListMIC) != 0 {
			serverResult <- errors.New("invalid final SPNEGO response")
			return
		}
		authenticate := finalSPNEGO.ResponseToken
		ntResponse, _, readErr := readNTLMSSPSecurityBuffer(authenticate, 20, ntlmSSPAuthHeaderSize)
		if readErr != nil || len(ntResponse) < 16+32+4 {
			serverResult <- errors.New("invalid NTLM AUTHENTICATE response")
			return
		}
		var clientChallenge, timestamp [8]byte
		copy(timestamp[:], ntResponse[24:32])
		copy(clientChallenge[:], ntResponse[32:40])
		password := []byte("Password")
		response, readErr := ComputeNTLMv2Response("User", "Domain", password, challenge.ServerChallenge, clientChallenge, timestamp, challenge.TargetInfo)
		clear(password)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		defer response.Purge()
		if !bytes.Equal(ntResponse[:16], response.NTProof[:]) || !bytes.Equal(ntResponse[16:44], response.NTResponse[16:44]) {
			serverResult <- errors.New("NTLM AUTHENTICATE proof does not match the challenge")
			return
		}
		authenticateCopy := append([]byte(nil), authenticate...)
		defer clear(authenticateCopy)
		gotMIC := append([]byte(nil), authenticateCopy[72:88]...)
		clear(authenticateCopy[72:88])
		mac := hmac.New(md5.New, response.SessionBaseKey[:])
		_, _ = mac.Write(MarshalNTLMSSPNegotiate())
		_, _ = mac.Write(challengeBytes)
		_, _ = mac.Write(authenticateCopy)
		if !hmac.Equal(gotMIC, mac.Sum(nil)) {
			serverResult <- errors.New("NTLM AUTHENTICATE MIC does not match the negotiation transcript")
			return
		}
		clear(gotMIC)
		clientInfo := ntResponse[16+28 : len(ntResponse)-4]
		pairs, pairErr := ParseNTLMv2AVPairs(clientInfo)
		if pairErr != nil {
			serverResult <- pairErr
			return
		}
		var targetNameSeen, channelBindingSeen, micFlagSeen bool
		wantTargetName, nameErr := NTLMv2TargetName("rdp.test")
		if nameErr != nil {
			serverResult <- nameErr
			return
		}
		defer clear(wantTargetName)
		wantChannelBinding, bindingErr := NTLMv2ChannelBindings(tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{serverLeaf}})
		if bindingErr != nil {
			serverResult <- bindingErr
			return
		}
		for _, pair := range pairs {
			switch pair.ID {
			case ntlmAvTargetName:
				targetNameSeen = bytes.Equal(pair.Value, wantTargetName)
			case ntlmAvChannelBindings:
				channelBindingSeen = bytes.Equal(pair.Value, wantChannelBinding[:])
			case ntlmAvFlags:
				micFlagSeen = binary.LittleEndian.Uint32(pair.Value)&0x2 != 0
			}
		}
		if !targetNameSeen || !channelBindingSeen || !micFlagSeen {
			serverResult <- errors.New("AUTHENTICATE omitted or changed TLS target/channel-binding AV_PAIRs or MIC_PRESENT")
			return
		}
		serverSecurity, readErr := newNTLMSSPSecurityContext(response.SessionBaseKey, challenge.Flags, false)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		defer serverSecurity.Close()
		clientHash, readErr := serverSecurity.inbound.unwrap(finalRequest.PubKeyAuth)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		defer clear(clientHash)
		publicKey, readErr := credSSPSubjectPublicKey(serverLeaf)
		if readErr != nil {
			serverResult <- readErr
			return
		}
		defer clear(publicKey)
		wantClientHash := credSSPPublicKeyHash([]byte(credSSPClientBindingMagic), finalRequest.ClientNonce, publicKey)
		if !bytes.Equal(clientHash, wantClientHash[:]) {
			serverResult <- errors.New("client pubKeyAuth does not bind this TLS certificate")
			return
		}
		serverHash := credSSPPublicKeyHash([]byte(credSSPServerBindingMagic), finalRequest.ClientNonce, publicKey)
		sealedServerHash, readErr := serverSecurity.outbound.wrap(serverHash[:])
		if readErr != nil {
			serverResult <- readErr
			return
		}
		serverResponse, readErr := MarshalTSRequest(TSRequest{Version: 5, PubKeyAuth: sealedServerHash})
		if readErr != nil || writeFull(tlsConn, serverResponse) != nil {
			serverResult <- errors.New("could not send server pubKeyAuth")
			return
		}
		serverResult <- nil
	}()

	transport, err := DialHybrid(context.Background(), TransportConfig{Address: listener.Addr().String(), TLSFingerprint: pin, TLSRoots: roots, TLSServerName: "rdp.test", DialTimeout: time.Second})
	if err != nil {
		t.Fatalf("DialHybrid: %v", err)
	}
	session, err := transport.EstablishCredSSP(context.Background(), CredSSPClientConfig{Version: 6, Username: "User", Domain: "Domain", Password: []byte("Password"), Timeout: 2 * time.Second})
	if err != nil {
		_ = transport.Close()
		t.Fatalf("EstablishCredSSP: %v", err)
	}
	if session == nil || session.security == nil || session.version != 5 {
		t.Fatal("CredSSP session was not retained after server binding")
	}
	session.Close()
	_ = transport.Close()
	if err := <-serverResult; err != nil {
		t.Fatalf("fake CredSSP server: %v", err)
	}
}

func spnegoChallengeForTest(challenge []byte) []byte {
	state := derWrap(0xa0, derWrap(0x0a, []byte{1}))
	mechanism, _ := asn1.Marshal(ntlmOID)
	selected := derWrap(0xa1, mechanism)
	token := derWrap(0xa2, derWrap(0x04, challenge))
	fields := append(append(state, selected...), token...)
	return derWrap(0xa1, derWrap(0x30, fields))
}

func TestNTLMCurrentFiletimeIsLittleEndianAndNonzero(t *testing.T) {
	got := ntlmCurrentFiletime()
	if binary.LittleEndian.Uint64(got[:]) == 0 {
		t.Fatal("FILETIME unexpectedly zero")
	}
}

func TestEstablishCredSSPHonorsCancellationBeforeSending(t *testing.T) {
	clientRaw, serverRaw := net.Pipe()
	defer serverRaw.Close()
	clientTLS := tls.Client(clientRaw, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) //nolint:gosec -- no handshake or network data is permitted in this cancellation test.
	transport := &Transport{Conn: clientTLS, targetServerName: "rdp.test"}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := transport.EstablishCredSSP(ctx, CredSSPClientConfig{Version: 6, Username: "User", Password: []byte("Password")})
	if !errors.Is(err, ErrCredSSPClient) {
		t.Fatalf("cancelled context error = %v, want ErrCredSSPClient", err)
	}
	if err := serverRaw.SetReadDeadline(time.Now().Add(25 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var one [1]byte
	if n, readErr := serverRaw.Read(one[:]); n != 0 || readErr == nil {
		t.Fatalf("cancelled exchange wrote %d bytes to TLS peer (err=%v)", n, readErr)
	}
	_ = transport.Close()
}

func TestReadTSRequestLeavesSchemaValidationToParser(t *testing.T) {
	malformed := derWrap(0x30, derWrap(0xa0, derWrap(0x02, []byte{1}))) // CredSSP version 1 is outside the supported range.
	framed, err := readTSRequest(bytes.NewReader(malformed))
	if err != nil {
		t.Fatalf("valid DER framing rejected: %v", err)
	}
	defer clear(framed)
	if _, err := ParseTSRequest(framed); !errors.Is(err, ErrCredSSPMessage) {
		t.Fatalf("schema parser error = %v, want ErrCredSSPMessage", err)
	}
}

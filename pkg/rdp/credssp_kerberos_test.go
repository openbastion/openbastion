package rdp

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/go-krb5/krb5/gssapi"
	"github.com/go-krb5/krb5/iana/etypeID"
	"github.com/go-krb5/krb5/iana/keyusage"
	"github.com/go-krb5/krb5/keytab"
	"github.com/go-krb5/krb5/messages"
	"github.com/go-krb5/krb5/types"
)

// CredSSP with Kerberos (ADR-0100, increment 2) against a CredSSP server of this test, over pinned
// TLS, written from MS-CSSP and RFC 4121 apart from the client: it reads the NegTokenInit and its
// AP-REQ, answers with the AP-REP (and its mechListMIC, signed by the library's own RFC 4121 code),
// checks the client's mechListMIC and pubKeyAuth, sends its pubKeyAuth, and opens authInfo. The
// tickets are the test's (kerberosTickets is stubbed): the real KDC is TestKerberos_AgainstAnMITKDC's.

// kerberosHarness says how the test's server behaves.
type kerberosHarness struct {
	serverMIC      bool                                // the AP-REP's NegTokenResp carries the server's mechListMIC
	state          uint64                              // its negState: 0 accept-completed, 1 accept-incomplete, 3 request-mic
	wantClientMIC  bool                                // the client must answer with its mechListMIC
	corruptBinding bool                                // the server's pubKeyAuth binds another certificate
	answer         func(acceptor *testAcceptor) []byte // replaces the server's first negoToken
	// real, when set, takes the tickets from a real KDC, and has the server read the AP-REQ with the
	// service's key alone, as Windows would (TestCredSSPKerberos_AgainstAnMITKDC).
	real *realKerberos
}

type realKerberos struct {
	config         KerberosConfig
	user, password string
	keytab         *keytab.Keytab
}

// parseNegTokenInitForTest reads a NegTokenInit: its mechanism list (as DER and as OIDs) and its
// mechToken.
func parseNegTokenInitForTest(t *testing.T, token []byte) ([]byte, []asn1.ObjectIdentifier, []byte) {
	t.Helper()
	var outer asn1.RawValue
	if _, err := asn1.Unmarshal(token, &outer); err != nil || outer.Class != asn1.ClassApplication || outer.Tag != 0 {
		t.Fatalf("not an InitialContextToken: %v", err)
	}
	var oid asn1.ObjectIdentifier
	rest, err := asn1.Unmarshal(outer.Bytes, &oid)
	if err != nil || !oid.Equal(spnegoOID) {
		t.Fatalf("not SPNEGO: %v", err)
	}
	var choice, seq asn1.RawValue
	if _, err := asn1.Unmarshal(rest, &choice); err != nil || choice.Tag != 0 {
		t.Fatal("not a negTokenInit")
	}
	if _, err := asn1.Unmarshal(choice.Bytes, &seq); err != nil {
		t.Fatal(err)
	}
	var mechTypes []byte
	var mechs []asn1.ObjectIdentifier
	var mechToken []byte
	for body := seq.Bytes; len(body) > 0; {
		var field asn1.RawValue
		next, err := asn1.Unmarshal(body, &field)
		if err != nil {
			t.Fatal(err)
		}
		body = next
		switch field.Tag {
		case 0:
			mechTypes = field.Bytes
			if _, err := asn1.Unmarshal(field.Bytes, &mechs); err != nil {
				t.Fatal(err)
			}
		case 2:
			if _, err := asn1.Unmarshal(field.Bytes, &mechToken); err != nil {
				t.Fatal(err)
			}
		default:
			t.Fatalf("a negTokenInit field [%d]", field.Tag)
		}
	}
	return mechTypes, mechs, mechToken
}

// negTokenRespForTest is a NegTokenResp: negState, supportedMech, responseToken, mechListMIC.
func negTokenRespForTest(state uint64, mech asn1.ObjectIdentifier, response, mic []byte) []byte {
	enum, _ := asn1.Marshal(asn1.Enumerated(state))
	oid, _ := asn1.Marshal(mech)
	fields := append(derWrap(0xa0, enum), derWrap(0xa1, oid)...)
	if len(response) != 0 {
		fields = append(fields, derWrap(0xa2, derWrap(0x04, response))...)
	}
	if len(mic) != 0 {
		fields = append(fields, derWrap(0xa3, derWrap(0x04, mic))...)
	}
	return derWrap(0xa1, derWrap(0x30, fields))
}

// acceptorMIC is the server's MIC over data, by the library's RFC 4121 code.
func (a *testAcceptor) acceptorMIC(data []byte) []byte {
	a.t.Helper()
	key, keyFlag := a.key()
	token := gssapi.MICToken{Flags: gssapi.MICTokenFlagSentByAcceptor | keyFlag, SndSeqNum: a.sendSeq, Payload: data}
	if err := token.SetChecksum(key, keyusage.GSSAPI_ACCEPTOR_SIGN); err != nil {
		a.t.Fatal(err)
	}
	raw, err := token.Marshal()
	if err != nil {
		a.t.Fatal(err)
	}
	a.sendSeq++
	return raw
}

// verifyInitiatorMIC checks the client's MIC over data, by the library's RFC 4121 code.
func (a *testAcceptor) verifyInitiatorMIC(data, raw []byte) error {
	key, keyFlag := a.key()
	var token gssapi.MICToken
	if err := token.Unmarshal(raw, false); err != nil {
		return err
	}
	if token.SndSeqNum != a.recvSeq || token.Flags != keyFlag {
		return errors.New("the client's MIC: sequence or flags")
	}
	token.Payload = data
	if ok, err := token.Verify(key, keyusage.GSSAPI_INITIATOR_SIGN); !ok {
		return err
	}
	a.recvSeq++
	return nil
}

func stubKerberosTickets(t *testing.T, sessionKey types.EncryptionKey) {
	t.Helper()
	saved := kerberosTickets
	kerberosTickets = func(cfg KerberosConfig, user string, password []byte) (messages.Ticket, types.EncryptionKey, error) {
		if user != "User" || string(password) != "Password" || cfg.ServicePrincipal != "TERMSRV/rdp.test" {
			return messages.Ticket{}, types.EncryptionKey{}, kerberosRefused("the test's KDC refuses")
		}
		return testTicket(), sessionKey, nil
	}
	t.Cleanup(func() { kerberosTickets = saved })
}

func runKerberosCredSSP(t *testing.T, h kerberosHarness) (*CredSSPClientSession, error, error) {
	t.Helper()
	certificate, roots, pin := rdpTestCertificate(t)
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	acceptor := &testAcceptor{t: t, sessionKey: testKey(t, etypeID.AES256_CTS_HMAC_SHA1_96)}
	user, password := "User", "Password"
	kerberos := KerberosConfig{Realm: "OPENBASTION.TEST", KDCs: []string{"kdc.openbastion.test:88"}, ServicePrincipal: "TERMSRV/rdp.test"}
	if h.real != nil {
		user, password, kerberos = h.real.user, h.real.password, h.real.config
	} else {
		stubKerberosTickets(t, acceptor.sessionKey)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverResult := make(chan error, 1)
	go func() {
		// The acceptor's helpers end this goroutine on a failure (t.Fatalf, runtime.Goexit): the
		// deferred send still tells the test, which would otherwise wait forever.
		result := errors.New("the server stopped on a failure")
		defer func() { serverResult <- result }()
		result = func() error {
			conn, err := listener.Accept()
			if err != nil {
				return err
			}
			defer conn.Close()
			if _, err := readTestTPKT(conn); err != nil {
				return err
			}
			if err := writeFull(conn, connectionConfirm(protocolHybrid)); err != nil {
				return err
			}
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			defer tlsConn.Close()
			if err := tlsConn.Handshake(); err != nil {
				return err
			}
			// A client that stops answering fails the test, it does not hang it.
			_ = tlsConn.SetDeadline(time.Now().Add(5 * time.Second))
			raw, err := readTSRequest(tlsConn)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte("NTLMSSP")) {
				return errors.New("NTLM in a Kerberos exchange")
			}
			initial, err := ParseTSRequest(raw)
			if err != nil || len(initial.NegoTokens) != 1 {
				return errors.New("the initial TSRequest")
			}
			mechTypes, mechs, apReq := parseNegTokenInitForTest(t, initial.NegoTokens[0])
			if len(mechs) != 1 || !mechs[0].Equal(oidKerberos5) {
				return errors.New("the client offered another mechanism than Kerberos 5 alone")
			}
			if h.real != nil {
				_, message, err := gssUnframe(apReq)
				if err != nil {
					return err
				}
				acceptor.readAPReqWith(message, h.real.keytab)
			} else {
				acceptor.readAPReq(apReq)
			}
			var answer []byte
			switch {
			case h.answer != nil:
				answer = h.answer(acceptor)
			case h.serverMIC:
				// The AP-REP first: the acceptor's subkey it carries signs the MIC.
				rep := acceptor.apRep(true, acceptor.auth.CTime, acceptor.auth.Cusec)
				answer = negTokenRespForTest(h.state, oidKerberos5, rep, acceptor.acceptorMIC(mechTypes))
			default:
				answer = negTokenRespForTest(h.state, oidKerberos5, acceptor.apRep(true, acceptor.auth.CTime, acceptor.auth.Cusec), nil)
			}
			out, _ := MarshalTSRequest(TSRequest{Version: 6, NegoTokens: [][]byte{answer}})
			if err := writeFull(tlsConn, out); err != nil {
				return err
			}
			raw, err = readTSRequest(tlsConn)
			if err != nil {
				return err
			}
			binding, err := ParseTSRequest(raw)
			if err != nil || len(binding.PubKeyAuth) == 0 || len(binding.ClientNonce) != 32 {
				return errors.New("the client's pubKeyAuth TSRequest")
			}
			if h.wantClientMIC {
				if len(binding.NegoTokens) != 1 {
					return errors.New("no mechListMIC from the client")
				}
				resp, err := parseSPNEGONegTokenResp(binding.NegoTokens[0], oidKerberos5)
				if err != nil || acceptor.verifyInitiatorMIC(mechTypes, resp.MechanismListMIC) != nil {
					return errors.New("the client's mechListMIC does not verify")
				}
			} else if len(binding.NegoTokens) != 0 {
				return errors.New("a mechListMIC nobody asked for")
			}
			publicKey, err := credSSPSubjectPublicKey(leaf)
			if err != nil {
				return err
			}
			clientHash := acceptor.unwrap(binding.PubKeyAuth)
			want := credSSPPublicKeyHash([]byte(credSSPClientBindingMagic), binding.ClientNonce, publicKey)
			if !bytes.Equal(clientHash, want[:]) {
				return errors.New("the client's pubKeyAuth does not bind this certificate")
			}
			serverHash := credSSPPublicKeyHash([]byte(credSSPServerBindingMagic), binding.ClientNonce, publicKey)
			if h.corruptBinding {
				serverHash[0] ^= 0xff
			}
			out, _ = MarshalTSRequest(TSRequest{Version: 6, PubKeyAuth: acceptor.wrap(serverHash[:], 0, 0)})
			if err := writeFull(tlsConn, out); err != nil {
				return err
			}
			if h.corruptBinding {
				_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
				var one [1]byte
				if n, _ := tlsConn.Read(one[:]); n != 0 {
					return errors.New("the client delegated after a wrong server binding")
				}
				return nil
			}
			raw, err = readTSRequest(tlsConn)
			if err != nil {
				return err
			}
			if bytes.Contains(raw, []byte{'P', 0, 'a', 0, 's', 0, 's', 0}) {
				return errors.New("the password in clear in authInfo")
			}
			authInfo, err := ParseTSRequest(raw)
			if err != nil || !tsRequestContainsOnlyVersionAndAuthInfo(raw) {
				return errors.New("the authInfo TSRequest")
			}
			domain, gotUser, gotPassword, err := parseCredSSPPasswordCredentialsForTest(acceptor.unwrap(authInfo.AuthInfo))
			if err != nil || domain != "RDP" || gotUser != user || gotPassword != password {
				return errors.New("the delegated credentials")
			}
			return nil
		}()
	}()
	transport, err := DialHybrid(context.Background(), TransportConfig{Address: listener.Addr().String(), TLSFingerprint: pin, TLSRoots: roots,
		TLSServerName: "rdp.test", DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	session, clientErr := transport.EstablishCredSSP(context.Background(), CredSSPClientConfig{Version: 6, Username: user, Domain: "RDP",
		Password: []byte(password), Timeout: 10 * time.Second, Kerberos: &kerberos})
	if clientErr != nil {
		_ = transport.Close()
	}
	return session, clientErr, <-serverResult
}

func TestCredSSPKerberos_TheWholeExchange(t *testing.T) {
	for name, h := range map[string]kerberosHarness{
		"completed, no MIC":           {state: spnegoStateAcceptCompleted},
		"completed, the server's MIC": {state: spnegoStateAcceptCompleted, serverMIC: true, wantClientMIC: true},
		"incomplete, a MIC asked":     {state: spnegoStateAcceptIncomplete, wantClientMIC: true},
		"request-mic":                 {state: spnegoStateRequestMIC, serverMIC: true, wantClientMIC: true},
	} {
		t.Run(name, func(t *testing.T) {
			session, clientErr, serverErr := runKerberosCredSSP(t, h)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("client %v, server %v", clientErr, serverErr)
			}
			if !session.credentialsDelegated {
				t.Fatal("no credentials delegated")
			}
			session.Close()
		})
	}
}

func TestCredSSPKerberos_RefusesWhatATargetMayNotSend(t *testing.T) {
	ntlmAnswer := func(*testAcceptor) []byte {
		return negTokenRespForTest(spnegoStateAcceptIncomplete, ntlmOID, ntlmSSPTestChallenge(ntlmSSPNegotiateFlags, nil), nil)
	}
	for name, h := range map[string]kerberosHarness{
		"another server binding": {corruptBinding: true},
		"NTLM in answer":         {answer: ntlmAnswer},
		"no AP-REP": {answer: func(*testAcceptor) []byte {
			return negTokenRespForTest(spnegoStateAcceptCompleted, oidKerberos5, nil, nil)
		}},
		"a KRB-ERROR": {answer: func(*testAcceptor) []byte {
			kerr := messages.NewKRBError(types.NewPrincipalName(2, "TERMSRV/rdp.test"), "OPENBASTION.TEST", 37, "")
			raw, _ := kerr.Marshal()
			return negTokenRespForTest(spnegoStateAcceptIncomplete, oidKerberos5, gssFrame(gssTokenError, raw), nil)
		}},
		"a forged MIC": {answer: func(a *testAcceptor) []byte {
			rep := a.apRep(true, a.auth.CTime, a.auth.Cusec)
			mic := a.acceptorMIC([]byte("not the mechanism list"))
			return negTokenRespForTest(spnegoStateAcceptCompleted, oidKerberos5, rep, mic)
		}},
		"an AP-REP of another time": {answer: func(a *testAcceptor) []byte {
			return negTokenRespForTest(spnegoStateAcceptCompleted, oidKerberos5, a.apRep(true, a.auth.CTime.Add(time.Second), a.auth.Cusec), nil)
		}},
	} {
		t.Run(name, func(t *testing.T) {
			session, clientErr, _ := runKerberosCredSSP(t, h)
			if clientErr == nil || session != nil || !errors.Is(clientErr, ErrCredSSPClient) {
				t.Fatalf("the client went on: %v", clientErr)
			}
		})
	}
}

// A KDC that refuses ends the exchange before anything is sent to the target: nothing of NTLM
// either.
func TestCredSSPKerberos_NoFallbackToNTLM(t *testing.T) {
	stubKerberosTickets(t, testKey(t, etypeID.AES256_CTS_HMAC_SHA1_96))
	certificate, roots, pin := rdpTestCertificate(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sent := make(chan []byte, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readTestTPKT(conn)
		_ = writeFull(conn, connectionConfirm(protocolHybrid))
		tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
		defer tlsConn.Close()
		_ = tlsConn.Handshake()
		_ = tlsConn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 4096)
		n, _ := tlsConn.Read(buf)
		sent <- buf[:n]
	}()
	transport, err := DialHybrid(context.Background(), TransportConfig{Address: listener.Addr().String(), TLSFingerprint: pin, TLSRoots: roots,
		TLSServerName: "rdp.test", DialTimeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = transport.EstablishCredSSP(context.Background(), CredSSPClientConfig{Version: 6, Username: "User", Domain: "RDP",
		Password: []byte("wrong"), Timeout: 2 * time.Second,
		Kerberos: &KerberosConfig{Realm: "OPENBASTION.TEST", KDCs: []string{"kdc.openbastion.test:88"}, ServicePrincipal: "TERMSRV/rdp.test"}})
	if !errors.Is(err, ErrCredSSPClient) || !strings.Contains(err.Error(), "the test's KDC refuses") {
		t.Fatalf("a refused ticket: %v", err)
	}
	if got := <-sent; len(got) != 0 {
		t.Fatalf("%d byte(s) sent to the target after the KDC refused", len(got))
	}
}

// The whole CredSSP exchange with tickets from a real KDC (MIT krb5 in Docker, KERBEROS_INTEROP=1):
// the client obtains them over TCP with pre-authentication, and the test's CredSSP server reads the
// AP-REQ with the service's key alone, then everything goes as with Windows, authInfo included.
func TestCredSSPKerberos_AgainstAnMITKDC(t *testing.T) {
	userPassword, servicePassword := "Op-kerberos-1", "Svc-kerberos-2"
	kdc := startMITKDC(t, userPassword, servicePassword)
	kt := keytab.New()
	for _, etype := range []int32{etypeID.AES256_CTS_HMAC_SHA1_96, etypeID.AES128_CTS_HMAC_SHA1_96} {
		if err := kt.AddEntry(kdcService, kdcRealm, servicePassword, time.Now(), 1, etype); err != nil {
			t.Fatal(err)
		}
	}
	for name, h := range map[string]kerberosHarness{
		"completed, no MIC":           {state: spnegoStateAcceptCompleted},
		"completed, the server's MIC": {state: spnegoStateAcceptCompleted, serverMIC: true, wantClientMIC: true},
	} {
		t.Run(name, func(t *testing.T) {
			h.real = &realKerberos{config: KerberosConfig{Realm: kdcRealm, KDCs: []string{kdc}, ServicePrincipal: kdcService, Timeout: 10 * time.Second},
				user: "operator", password: userPassword, keytab: kt}
			session, clientErr, serverErr := runKerberosCredSSP(t, h)
			if clientErr != nil || serverErr != nil {
				t.Fatalf("client %v, server %v", clientErr, serverErr)
			}
			session.Close()
		})
	}
	// A wrong password: the KDC refuses before the target hears anything, and says so as NTLM does.
	h := kerberosHarness{real: &realKerberos{config: KerberosConfig{Realm: kdcRealm, KDCs: []string{kdc}, ServicePrincipal: kdcService},
		user: "operator", password: "wrong", keytab: kt}}
	if _, clientErr, _ := runKerberosCredSSP(t, h); !errors.Is(clientErr, ErrTargetCredentialsRefused) {
		t.Fatalf("a wrong password through CredSSP: %v", clientErr)
	}
}

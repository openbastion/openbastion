package rdp

// ADR-0071, the Windows validation, second isolation. CI run #15 measured that Windows keeps the
// connection open 30 s after authInfo, and closes it 1 ms after any Connect-Initial, whatever it
// says (TestRDPWindowsIsolation_MCSConnectInitial). That does not prove authInfo accepted: Windows
// never answers authInfo, and a refusal may only show when the next packet is read. This test
// gives that measure its counter-proof, and asks the two other questions it leaves:
//
//   - an authInfo Windows must refuse (one ciphertext byte flipped, so its checksum fails): if
//     Windows closes at once, "open after authInfo" means accepted, and the Connect-Initial is the
//     cause; if it waits and closes 1 ms after the Connect-Initial just the same, the measure said
//     nothing, and authInfo is the suspect;
//   - the domain of TSPasswordCreds, empty in the client: "." and the NetBIOS name the CHALLENGE
//     gives, the two a Windows client sends for a local account;
//   - the protocols the X.224 request names. CI run #19 had Windows log, at each Connect-Initial,
//     RDP_SEC leaving FStatePassthrough for FStateError on FEventCheckAndCompleteReadsFailed
//     (0x8007139F, ERROR_INVALID_STATE): Windows does not expect to read at all, whatever the
//     packet says. The client asks for HYBRID alone; MS-RDPBCGR 2.2.1.1.1 says SSL SHOULD come with
//     it, and Windows clients also ask for HYBRID_EX, after which the server sends the Early User
//     Authorization Result (2.2.10.2) before any MCS byte.
//
// (Run #16 settled TLS: Windows Server 2022 negotiates TLS 1.2 with this client.)
//
// Nothing here is a fix: each case is a fresh connection, and what Windows does is the result.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
	"unicode/utf16"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

type authInfoCase struct {
	name, source string
	// requested is RDP_NEG_REQ.requestedProtocols; 0 keeps the client's (HYBRID alone).
	requested uint32
	// directNTLM drops SPNEGO, as FreeRDP does (CredSSPClientConfig.directNTLM).
	directNTLM bool
	// seal replaces the client's sealing of authInfo; nil keeps it. domain is the one it names.
	seal func(user, password string) func(*NTLMSSPClientSecurityContext, NTLMSSPChallenge, []byte) ([]byte, error)
}

// challengeName is the AV_PAIR id of the CHALLENGE's TargetInfo, decoded; "" when absent.
func challengeName(challenge NTLMSSPChallenge, id uint16) string {
	pairs, err := ParseNTLMv2AVPairs(challenge.TargetInfo)
	if err != nil {
		return ""
	}
	for _, pair := range pairs {
		if pair.ID == id && len(pair.Value)%2 == 0 {
			units := make([]uint16, len(pair.Value)/2)
			for i := range units {
				units[i] = binary.LittleEndian.Uint16(pair.Value[2*i:])
			}
			return string(utf16.Decode(units))
		}
	}
	return ""
}

// sealWithDomain seals TSPasswordCreds naming domain instead of the client's empty one. The NTLM
// exchange before it is the client's, unchanged.
func sealWithDomain(domain func(NTLMSSPChallenge) string) func(user, password string) func(*NTLMSSPClientSecurityContext, NTLMSSPChallenge, []byte) ([]byte, error) {
	return func(user, password string) func(*NTLMSSPClientSecurityContext, NTLMSSPChallenge, []byte) ([]byte, error) {
		return func(security *NTLMSSPClientSecurityContext, challenge NTLMSSPChallenge, _ []byte) ([]byte, error) {
			name := domain(challenge)
			if name == "" {
				return nil, fmt.Errorf("the CHALLENGE names no domain")
			}
			credentials, err := marshalCredSSPPasswordCredentials(name, user, []byte(password))
			if err != nil {
				return nil, err
			}
			defer clear(credentials)
			return security.WrapClientToServer(credentials)
		}
	}
}

func authInfoCases() []authInfoCase {
	return []authInfoCase{
		{name: "authInfo as the client seals it", source: "the control: the client as it is"},
		{name: "authInfo, one ciphertext byte flipped", source: "MS-NLMP 3.4.4: the checksum fails, Windows must refuse it",
			seal: func(string, string) func(*NTLMSSPClientSecurityContext, NTLMSSPChallenge, []byte) ([]byte, error) {
				return func(security *NTLMSSPClientSecurityContext, _ NTLMSSPChallenge, credentials []byte) ([]byte, error) {
					sealed, err := security.WrapClientToServer(credentials)
					if err == nil {
						sealed[len(sealed)-1] ^= 0x01
					}
					return sealed, err
				}
			}},
		{name: `TSPasswordCreds domain "."`, source: "the local machine, as a Windows client names it",
			seal: sealWithDomain(func(NTLMSSPChallenge) string { return "." })},
		{name: "TSPasswordCreds domain: NetBIOS computer name", source: "MsvAvNbComputerName of the CHALLENGE",
			seal: sealWithDomain(func(c NTLMSSPChallenge) string { return challengeName(c, ntlmAvNbComputerName) })},
		{name: "requested SSL|HYBRID", source: "MS-RDPBCGR 2.2.1.1.1: with HYBRID, SSL SHOULD be set", requested: protocolSSL | protocolHybrid},
		{name: "direct NTLM, no SPNEGO", source: "run #21: FreeRDP opens a full session this way (\"Using direct NTLM\")", directNTLM: true},
		{name: "direct NTLM, requested SSL|HYBRID", source: "FreeRDP's request and CredSSP, both", directNTLM: true, requested: protocolSSL | protocolHybrid},
		{name: "requested SSL|HYBRID|HYBRID_EX", source: "what Windows clients ask; 2.2.10.2: the Early User Authorization Result follows authInfo", requested: protocolSSL | protocolHybrid | protocolHybridEx},
	}
}

const (
	protocolSSL      = uint32(0x00000001)
	protocolHybridEx = uint32(0x00000008)
)

// isolationDial is DialHybrid with other requested protocols: the same X.224 request otherwise, the
// same pin, roots and name. It returns the protocol the server selected.
func isolationDial(ctx context.Context, address, pin, name string, roots *x509.CertPool, requested uint32) (*Transport, uint32, error) {
	if requested == 0 {
		transport, err := DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
		return transport, protocolHybrid, err
	}
	config, err := tlspin.ServerConfig(pin, roots, name)
	if err != nil {
		return nil, 0, err
	}
	expected, err := tlspin.ParseFingerprint(pin)
	if err != nil {
		return nil, 0, err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, 0, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	request := connectionRequest()
	binary.LittleEndian.PutUint32(request[15:19], requested)
	if err := writeFull(conn, request); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	selected, err := readSelectedProtocol(conn)
	if err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, 0, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return &Transport{Conn: tlsConn, targetServerName: name, expectedPin: expected}, selected, nil
}

// readSelectedProtocol reads the X.224 Connection Confirm and returns RDP_NEG_RSP.selectedProtocol.
func readSelectedProtocol(conn net.Conn) (uint32, error) {
	packet, err := readTPKTPacket(conn, maxTPKTPacket)
	if err != nil {
		return 0, err
	}
	if len(packet) != 19 || packet[5] != 0xd0 {
		return 0, fmt.Errorf("connection confirm: % x", packet)
	}
	if packet[11] != rdpNegResp {
		return 0, fmt.Errorf("negotiation failure %d", binary.LittleEndian.Uint32(packet[15:19]))
	}
	return binary.LittleEndian.Uint32(packet[15:19]), nil
}

// connectInitialSelecting is the client's Connect-Initial with serverSelectedProtocol set to what
// the server selected; for HYBRID, byte for byte the client's.
func connectInitialSelecting(settings MCSClientSettings, selected uint32) ([]byte, error) {
	blocks, err := marshalClientDataBlocks(settings)
	if err != nil {
		return nil, err
	}
	// The first block is CS_CORE; serverSelectedProtocol is the last field of its 212 bytes.
	binary.LittleEndian.PutUint32(blocks[4+208:4+212], selected)
	gcc, err := marshalGCCConferenceCreateRequest(blocks)
	if err != nil {
		return nil, err
	}
	mcs, err := marshalMCSConnectInitial(gcc)
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 7+len(mcs))
	packet[0] = 3
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[4:7], []byte{2, 0xf0, 0x80})
	copy(packet[7:], mcs)
	return packet, nil
}

func TestRDPWindowsIsolation_AuthInfo(t *testing.T) {
	if os.Getenv("RDP_WINDOWS") == "" {
		t.Skip("RDP_WINDOWS not set: this test needs a Windows target (test/integration/testdata/rdp/windows)")
	}
	address, user, password := os.Getenv("RDP_WINDOWS_ADDRESS"), os.Getenv("RDP_WINDOWS_USER"), os.Getenv("RDP_WINDOWS_PASSWORD")
	pin, name := os.Getenv("RDP_WINDOWS_PIN"), os.Getenv("RDP_WINDOWS_SERVER_NAME")
	raw, err := os.ReadFile(os.Getenv("RDP_WINDOWS_CA_FILE"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(raw) {
		t.Fatal("RDP_WINDOWS_CA_FILE holds no certificate")
	}
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	var report []string
	for _, c := range authInfoCases() {
		var names string
		cfg := CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second, directNTLM: c.directNTLM}
		var seal func(*NTLMSSPClientSecurityContext, NTLMSSPChallenge, []byte) ([]byte, error)
		if c.seal != nil {
			seal = c.seal(user, password)
		}
		cfg.sealAuthInfo = func(security *NTLMSSPClientSecurityContext, challenge NTLMSSPChallenge, credentials []byte) ([]byte, error) {
			names = fmt.Sprintf("NetBIOS %q/%q, DNS %q", challengeName(challenge, ntlmAvNbComputerName),
				challengeName(challenge, ntlmAvNbDomainName), challengeName(challenge, ntlmAvDNSComputerName))
			if seal != nil {
				return seal(security, challenge, credentials)
			}
			return security.WrapClientToServer(credentials)
		}
		result, connection := authInfoRun(address, pin, name, roots, c.requested, cfg, settings)
		line := fmt.Sprintf("%-46s | %s | after authInfo: %-32s | Connect-Initial: %s   [%s; CHALLENGE %s]",
			c.name, connection, result.openAfterAuthInfo, result.answer, c.source, names)
		t.Log(line)
		report = append(report, line)
		time.Sleep(2 * time.Second)
	}
	if dir := os.Getenv("RDP_WINDOWS_DUMP"); dir != "" {
		_ = os.WriteFile(filepath.Join(dir, "authinfo-isolation.txt"), []byte(strings.Join(report, "\n")+"\n"), 0o644)
	}
}

// authInfoRun is one case: dial, CredSSP with the case's authInfo, then (HYBRID_EX) the Early User
// Authorization Result, 10 s for Windows to close on its own, and the client's Connect-Initial
// naming the selected protocol. The second result names the protocol, the TLS version and suite.
func authInfoRun(address, pin, name string, roots *x509.CertPool, requested uint32, cfg CredSSPClientConfig, settings MCSClientSettings) (isolationResult, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport, selected, err := isolationDial(ctx, address, pin, name, roots, requested)
	if err != nil {
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("dial: %v", err)}, "-"
	}
	state := transport.Conn.ConnectionState()
	connection := fmt.Sprintf("selected 0x%x, %s %s", selected, tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
	packet, err := connectInitialSelecting(settings, selected)
	if err != nil {
		_ = transport.Close()
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("Connect-Initial: %v", err)}, connection
	}
	session, err := transport.EstablishCredSSP(ctx, cfg)
	if err != nil {
		_ = transport.Close()
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("CredSSP: %v", err)}, connection
	}
	defer session.Close()
	if selected&protocolHybridEx != 0 {
		var result [4]byte
		_ = transport.Conn.SetReadDeadline(time.Now().Add(10 * time.Second))
		if _, err := io.ReadFull(transport.Conn, result[:]); err != nil {
			return isolationResult{openAfterAuthInfo: fmt.Sprintf("no Early User Authorization Result: %v", err), answer: "not sent"}, connection
		}
		connection += fmt.Sprintf(", Early User Authorization Result 0x%08x", binary.LittleEndian.Uint32(result[:]))
	}
	return isolationAfterCredSSP(session, 10*time.Second, packet), connection
}

// The seam the cases use is the client's own path when nothing replaces it: the control's authInfo
// is the client's sealing, and a flipped byte is one byte.
func TestRDPWindowsIsolation_AuthInfoCasesAreWhatTheySay(t *testing.T) {
	cases := authInfoCases()
	if cases[0].seal != nil || cases[0].requested != 0 {
		t.Fatal("the control must be the client as it is")
	}
	for _, c := range cases[4:] {
		if c.seal != nil || (c.requested != 0 && c.requested&protocolHybrid == 0) || (c.requested == 0 && !c.directNTLM) {
			t.Fatalf("%s must change the requested protocols (HYBRID kept) or SPNEGO, and nothing else", c.name)
		}
	}
	// The Connect-Initial names what was selected: for HYBRID, the client's own; otherwise one byte.
	settings := MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second}
	want, err := MarshalMCSConnectInitial(settings)
	if err != nil {
		t.Fatal(err)
	}
	same, err := connectInitialSelecting(settings, protocolHybrid)
	if err != nil || !bytes.Equal(same, want) {
		t.Fatalf("HYBRID: not the client's Connect-Initial (%v)", err)
	}
	ex, err := connectInitialSelecting(settings, protocolHybridEx)
	if err != nil || len(ex) != len(want) {
		t.Fatalf("HYBRID_EX: %v", err)
	}
	diff := 0
	for i := range want {
		if ex[i] != want[i] {
			diff++
			if want[i] != byte(protocolHybrid) || ex[i] != byte(protocolHybridEx) {
				t.Fatalf("HYBRID_EX: byte %d is %#x, want the selected protocol", i, ex[i])
			}
		}
	}
	if diff != 1 {
		t.Fatalf("HYBRID_EX: %d bytes differ, want 1", diff)
	}
	challenge := NTLMSSPChallenge{TargetInfo: []byte{1, 0, 4, 0, 'W', 0, 'S', 0, 0, 0, 0, 0}}
	if got := challengeName(challenge, ntlmAvNbComputerName); got != "WS" {
		t.Fatalf("challengeName = %q, want WS", got)
	}
	if got := challengeName(challenge, ntlmAvDNSComputerName); got != "" {
		t.Fatalf("absent name = %q, want empty", got)
	}
}

// directNTLM is what it says: the first negoToken is the NTLM NEGOTIATE itself, not a SPNEGO
// negTokenInit; and without it, the client's is SPNEGO. (The rest of the direct exchange is judged
// against Windows: no fake server here speaks it.)
func TestEstablishCredSSPDirectNTLMSendsBareNTLM(t *testing.T) {
	for _, direct := range []bool{false, true} {
		certificate, roots, pin := rdpTestCertificate(t)
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		first := make(chan []byte, 1)
		go func() {
			defer close(first)
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()
			if _, err := readTestTPKT(conn); err != nil || writeFull(conn, connectionConfirm(protocolHybrid)) != nil {
				return
			}
			tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12})
			defer tlsConn.Close()
			raw, err := readTSRequest(tlsConn)
			if err != nil {
				return
			}
			request, err := ParseTSRequest(raw)
			if err == nil && len(request.NegoTokens) == 1 {
				first <- request.NegoTokens[0]
			}
		}()
		transport, err := DialHybrid(context.Background(), TransportConfig{Address: listener.Addr().String(), TLSFingerprint: pin, TLSRoots: roots, TLSServerName: "rdp.test", DialTimeout: time.Second})
		if err != nil {
			t.Fatal(err)
		}
		_, _ = transport.EstablishCredSSP(context.Background(), CredSSPClientConfig{Version: 6, Username: "User", Password: []byte("Password"), Timeout: time.Second, directNTLM: direct})
		_ = transport.Close()
		_ = listener.Close()
		token := <-first
		bare := bytes.HasPrefix(token, []byte("NTLMSSP\x00\x01\x00\x00\x00"))
		if bare != direct {
			t.Fatalf("directNTLM %v: first negoToken % x…, bare NTLM %v", direct, token[:min(len(token), 12)], bare)
		}
	}
}

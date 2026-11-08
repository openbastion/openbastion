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
//   - TLS 1.2 instead of what Go negotiates (TLS 1.3 when the server offers it).
//
// Nothing here is a fix: each case is a fresh connection, and what Windows does is the result.
//
//	RDP_WINDOWS=1 … go test ./pkg/rdp -run TestRDPWindowsIsolation -v

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
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
	tlsMax       uint16
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
		{name: "TLS 1.2", source: "the client offers TLS 1.3 to a server that has it", tlsMax: tls.VersionTLS12},
	}
}

// isolationDial is DialHybrid with the TLS version capped: the same X.224 request, pin, roots and
// name, so the transport is the client's in all but that.
func isolationDial(ctx context.Context, address, pin, name string, roots *x509.CertPool, tlsMax uint16) (*Transport, error) {
	if tlsMax == 0 {
		return DialHybrid(ctx, TransportConfig{Address: address, TLSFingerprint: pin, TLSRoots: roots, TLSServerName: name, DialTimeout: 10 * time.Second})
	}
	config, err := tlspin.ServerConfig(pin, roots, name)
	if err != nil {
		return nil, err
	}
	config.MaxVersion = tlsMax
	expected, err := tlspin.ParseFingerprint(pin)
	if err != nil {
		return nil, err
	}
	conn, err := (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(15 * time.Second))
	if err := writeFull(conn, connectionRequest()); err != nil {
		_ = conn.Close()
		return nil, err
	}
	if err := readConnectionConfirm(conn); err != nil {
		_ = conn.Close()
		return nil, err
	}
	tlsConn := tls.Client(conn, config)
	if err := tlsConn.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	_ = tlsConn.SetDeadline(time.Time{})
	return &Transport{Conn: tlsConn, targetServerName: name, expectedPin: expected}, nil
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
	packet, err := MarshalMCSConnectInitial(MCSClientSettings{DesktopWidth: 1280, DesktopHeight: 800, ClientName: "OpenBastion", Timeout: 15 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	var report []string
	for _, c := range authInfoCases() {
		var names string
		cfg := CredSSPClientConfig{Version: 6, Username: user, Password: []byte(password), Timeout: 15 * time.Second}
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
		result, connection := authInfoRun(address, pin, name, roots, c.tlsMax, cfg, packet)
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

// authInfoRun is one case: dial, CredSSP with the case's authInfo, 10 s for Windows to close on its
// own, then the client's Connect-Initial. The second result names the TLS version and suite.
func authInfoRun(address, pin, name string, roots *x509.CertPool, tlsMax uint16, cfg CredSSPClientConfig, packet []byte) (isolationResult, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	transport, err := isolationDial(ctx, address, pin, name, roots, tlsMax)
	if err != nil {
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("dial: %v", err)}, "-"
	}
	state := transport.Conn.ConnectionState()
	connection := fmt.Sprintf("%s %s", tls.VersionName(state.Version), tls.CipherSuiteName(state.CipherSuite))
	session, err := transport.EstablishCredSSP(ctx, cfg)
	if err != nil {
		_ = transport.Close()
		return isolationResult{openAfterAuthInfo: "not reached", answer: fmt.Sprintf("CredSSP: %v", err)}, connection
	}
	defer session.Close()
	return isolationAfterCredSSP(session, 10*time.Second, packet), connection
}

// The seam the cases use is the client's own path when nothing replaces it: the control's authInfo
// is the client's sealing, and a flipped byte is one byte.
func TestRDPWindowsIsolation_AuthInfoCasesAreWhatTheySay(t *testing.T) {
	cases := authInfoCases()
	if cases[0].seal != nil || cases[0].tlsMax != 0 {
		t.Fatal("the control must be the client as it is")
	}
	if cases[4].seal != nil || cases[4].tlsMax != tls.VersionTLS12 {
		t.Fatal("the TLS case must change the TLS version and nothing else")
	}
	challenge := NTLMSSPChallenge{TargetInfo: []byte{1, 0, 4, 0, 'W', 0, 'S', 0, 0, 0, 0, 0}}
	if got := challengeName(challenge, ntlmAvNbComputerName); got != "WS" {
		t.Fatalf("challengeName = %q, want WS", got)
	}
	if got := challengeName(challenge, ntlmAvDNSComputerName); got != "" {
		t.Fatalf("absent name = %q, want empty", got)
	}
}

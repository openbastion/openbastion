package engine

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/rdp"
)

// ADR-0100, increment 3: an account the Vault set to Kerberos gets a Kerberos session, and nothing
// else. The ticket names TERMSRV/<the pinned target name>, the name the certificate is verified
// against; a pinned IP address names no host, and the session is refused before anything is sent.

func TestRDPKerberosConfig_TheTicketIsForThePinnedName(t *testing.T) {
	cred := rdpTestCredentialWith(t, proxycore.Fetched{TargetDomain: "desk.corp.example.com", KerberosRealm: "CORP.EXAMPLE.COM", KerberosKDCs: []string{"dc1.corp.example.com:88"}})
	got, err := rdpKerberosConfig(cred, 7*time.Second)
	if err != nil || got.Realm != "CORP.EXAMPLE.COM" || got.ServicePrincipal != "TERMSRV/desk.corp.example.com" || got.KDCs[0] != "dc1.corp.example.com:88" || got.Timeout != 7*time.Second {
		t.Fatalf("%+v, %v", got, err)
	}
	for _, name := range []string{"", "10.0.0.5", "2001:db8::1"} {
		cred := rdpTestCredentialWith(t, proxycore.Fetched{TargetDomain: name, KerberosRealm: "CORP.EXAMPLE.COM", KerberosKDCs: []string{"dc1:88"}})
		if _, err := rdpKerberosConfig(cred, time.Second); !errors.Is(err, rdp.ErrRDPKerberos) {
			t.Errorf("a ticket for %q: %v", name, err)
		}
	}
}

// Against a target of this test, over real TCP and pinned TLS: with a realm and a KDC that does not
// answer, the session fails before one CredSSP byte reaches the target — no NTLM, ever. Without a
// realm, the same target receives the NTLM negotiation: the counter-proof that it would see one.
func TestRDPCodec_AKerberosAccountNeverSendsNTLM(t *testing.T) {
	closedKDC, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	kdc := closedKDC.Addr().String()
	_ = closedKDC.Close() // nothing listens there any more: the AS exchange cannot be made

	for name, realm := range map[string]string{"Kerberos": "CORP.EXAMPLE.COM", "NTLM (counter-proof)": ""} {
		t.Run(name, func(t *testing.T) {
			address, pin, roots, received := fakeHybridTarget(t)
			cred := rdpTestCredentialWith(t, proxycore.Fetched{TargetHost: address, TLSCertificateSHA256: pin, TargetDomain: "rdp.test",
				KerberosRealm: realm, KerberosKDCs: []string{kdc}})
			codec := &RDPCodec{TLSRoots: roots, DialTimeout: 2 * time.Second}
			_, err := codec.Open(context.Background(), cred)
			if err == nil {
				t.Fatal("the fake target cannot carry a session")
			}
			got := <-received
			if realm != "" {
				if !errors.Is(err, rdp.ErrRDPKerberos) || len(got) != 0 {
					t.Fatalf("a Kerberos account: %v; %d byte(s) reached the target", err, len(got))
				}
				var failure *proxycore.ScreenFailure
				if !errors.As(err, &failure) || failure.ScreenEndCode() != "kerberos_failed" {
					t.Fatalf("the failure: %v", err)
				}
				return
			}
			if !bytes.Contains(got, []byte("NTLMSSP")) {
				t.Fatalf("the counter-proof: the target saw no NTLM negotiation (%d bytes)", len(got))
			}
			// The same failed CredSSP on an NTLM account is no Kerberos failure.
			var failure *proxycore.ScreenFailure
			if !errors.As(err, &failure) || failure.ScreenEndCode() != "target_unreachable" {
				t.Fatalf("an NTLM account's failure: %v", err)
			}
		})
	}
}

func rdpTestCredentialWith(t *testing.T, f proxycore.Fetched) *proxycore.Credential {
	t.Helper()
	f.Type, f.Material, f.TargetUser = "password", []byte("temporary-password"), "operator"
	if f.TargetHost == "" {
		f.TargetHost = "rdp.example:3389"
	}
	if f.TLSCertificateSHA256 == "" {
		f.TLSCertificateSHA256 = strings.Repeat("0", 64)
	}
	cred, err := proxycore.NewCredentialFetcher(testMetadataVault{fetched: f}, "rdp-vnc-proxy").Fetch(context.Background(), "one-use")
	if err != nil {
		t.Fatal(err)
	}
	return cred
}

// fakeHybridTarget answers the X.224 request with PROTOCOL_HYBRID, completes TLS with a certificate
// for rdp.test, and reports what the client then sent, until it closes or for two seconds.
func fakeHybridTarget(t *testing.T) (string, string, *x509.CertPool, <-chan []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "rdp.test"}, DNSNames: []string{"rdp.test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(der)
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	sum := sha256.Sum256(der)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	received := make(chan []byte, 1)
	go func() {
		var got []byte
		defer func() { received <- got }()
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			return
		}
		if _, err := io.ReadFull(conn, make([]byte, int(header[2])<<8|int(header[3])-4)); err != nil {
			return
		}
		// TPKT, X.224 Connection Confirm, RDP_NEG_RSP selecting PROTOCOL_HYBRID (MS-RDPBCGR 2.2.1.2).
		confirm, _ := hex.DecodeString("030000130ed000001234000200080002000000")
		if _, err := conn.Write(confirm); err != nil {
			return
		}
		server := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}, MinVersion: tls.VersionTLS12})
		if err := server.Handshake(); err != nil {
			return
		}
		_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 8192)
		n, _ := io.ReadAtLeast(server, buf, 1)
		got = buf[:n]
	}()
	return listener.Addr().String(), hex.EncodeToString(sum[:]), roots, received
}

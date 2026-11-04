package rdp

import (
	"bytes"
	"crypto"
	"crypto/md5"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/pkg/tlspin"
)

func TestNTLMv2TargetNameUsesCanonicalRDPServicePrincipal(t *testing.T) {
	got, err := NTLMv2TargetName("RDP.Example.TEST.")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(got)
	want, ok := utf16LEFromUTF8([]byte("TERMSRV/rdp.example.test"))
	if !ok || !bytes.Equal(got, want) {
		t.Fatalf("target name = %x, want UTF-16LE TERMSRV/rdp.example.test (%x)", got, want)
	}
	clear(want)
	ipv6, err := NTLMv2TargetName("2001:db8::1")
	if err != nil {
		t.Fatalf("IPv6 target name: %v", err)
	}
	defer clear(ipv6)
	ipv6Want, _ := utf16LEFromUTF8([]byte("TERMSRV/2001:db8::1"))
	if !bytes.Equal(ipv6, ipv6Want) {
		t.Fatalf("IPv6 target name = %x, want %x", ipv6, ipv6Want)
	}
	clear(ipv6Want)
	for _, invalid := range []string{"", "rdp.example.test:3389", "rdp.example.test/other", "rdp.example.test\\other", "bad name", " rdp.example.test", "rdp.example.test ", "rdp..example.test", "-rdp.example.test", "rdp-.example.test", "rdp_name.example.test", "rdp*.example.test"} {
		if _, err := NTLMv2TargetName(invalid); !errors.Is(err, ErrNTLMv2Input) {
			t.Errorf("NTLMv2TargetName(%q) error = %v", invalid, err)
		}
	}
}

func TestNTLMv2ChannelBindingsUseTLSCertificateAndNTLMSerialization(t *testing.T) {
	cert, _, _ := rdpTestCertificate(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
	got, err := NTLMv2ChannelBindings(state)
	if err != nil {
		t.Fatal(err)
	}
	// Independent construction for an ECDSA/SHA-256 test certificate.
	certificateHash := sha256Sum(leaf.Raw)
	endpoint := append([]byte("tls-server-end-point:"), certificateHash...)
	unhashed := make([]byte, 20+len(endpoint))
	binary.LittleEndian.PutUint32(unhashed[16:20], uint32(len(endpoint)))
	copy(unhashed[20:], endpoint)
	want := md5Sum(unhashed)
	if got != want {
		t.Fatalf("channel binding = %x, want %x", got, want)
	}

	otherCert, _, _ := rdpTestCertificate(t)
	otherLeaf, err := x509.ParseCertificate(otherCert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	other, err := NTLMv2ChannelBindings(tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{otherLeaf}})
	if err != nil {
		t.Fatal(err)
	}
	if got == other {
		t.Fatal("different TLS peer certificates produced the same channel binding")
	}
	if _, err := NTLMv2ChannelBindings(tls.ConnectionState{}); !errors.Is(err, ErrNTLMv2ChannelBinding) {
		t.Fatalf("incomplete handshake error = %v", err)
	}
	if _, err := NTLMv2ChannelBindings(tls.ConnectionState{HandshakeComplete: true}); !errors.Is(err, ErrNTLMv2ChannelBinding) {
		t.Fatalf("missing peer certificate error = %v", err)
	}
}

func TestTLSserverEndpointHashRejectsAmbiguousCertificateAlgorithms(t *testing.T) {
	for _, algorithm := range []x509.SignatureAlgorithm{x509.PureEd25519, x509.UnknownSignatureAlgorithm} {
		if _, ok := tlsServerEndpointHash(algorithm); ok {
			t.Errorf("algorithm %v unexpectedly supported", algorithm)
		}
	}
	if got, ok := tlsServerEndpointHash(x509.SHA1WithRSA); !ok || got != crypto.SHA256 {
		t.Fatalf("SHA-1 certificate fallback = %v, %v; want SHA-256, true", got, ok)
	}
}

func sha256Sum(value []byte) []byte {
	sum := sha256.Sum256(value)
	return sum[:]
}

func md5Sum(value []byte) [16]byte {
	return md5.Sum(value)
}

func TestNTLMv2TargetInfoWithMICFlag_AddsOrSetsFlagAfterProof(t *testing.T) {
	base := ntlmSSPTestTargetInfo(t)
	withoutFlags := base[8:]
	for name, serverInfo := range map[string][]byte{
		"flag absent": withoutFlags,
		"flag zero":   append([]byte{6, 0, 4, 0, 0, 0, 0, 0}, withoutFlags...),
		"flag set":    base,
	} {
		t.Run(name, func(t *testing.T) {
			got, err := NTLMv2TargetInfoWithMICFlag(serverInfo)
			if err != nil {
				t.Fatal(err)
			}
			defer clear(got)
			pairs, err := ParseNTLMv2AVPairs(got)
			if err != nil {
				t.Fatal(err)
			}
			flags := 0
			for _, pair := range pairs {
				if pair.ID == ntlmAvFlags {
					flags++
					if binary.LittleEndian.Uint32(pair.Value) != 0x00000002 {
						t.Fatalf("MIC flags = %#x", binary.LittleEndian.Uint32(pair.Value))
					}
				}
			}
			if flags != 1 {
				t.Fatalf("found %d MIC flag AV_PAIRs", flags)
			}
		})
	}
}

func TestVerifyNTLMv2TLSPeerRequiresThePinnedLeafCertificate(t *testing.T) {
	cert, _, pinValue := rdpTestCertificate(t)
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatal(err)
	}
	state := tls.ConnectionState{HandshakeComplete: true, PeerCertificates: []*x509.Certificate{leaf}}
	pin, err := tlspin.ParseFingerprint(pinValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNTLMv2TLSPeer(state, pin); err != nil {
		t.Fatalf("correct pinned certificate rejected: %v", err)
	}
	_, _, impostorPinValue := rdpTestCertificate(t)
	impostorPin, err := tlspin.ParseFingerprint(impostorPinValue)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyNTLMv2TLSPeer(state, impostorPin); !errors.Is(err, ErrNTLMv2ChannelBinding) {
		t.Fatalf("impostor certificate error = %v, want ErrNTLMv2ChannelBinding", err)
	}
	if err := verifyNTLMv2TLSPeer(state, tlspin.Fingerprint{}); !errors.Is(err, ErrNTLMv2ChannelBinding) {
		t.Fatalf("missing pin error = %v, want ErrNTLMv2ChannelBinding", err)
	}
}

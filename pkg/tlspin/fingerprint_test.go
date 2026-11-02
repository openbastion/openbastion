package tlspin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"math/big"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseFingerprint(t *testing.T) {
	cert, leaf := targetCertificate(t, "target.example")
	pin := mustPin(t, cert.Certificate[0])
	if err := VerifyCertificate(cert.Certificate[0], pin); err != nil {
		t.Fatal(err)
	}
	if leaf == nil {
		t.Fatal("leaf certificate not parsed")
	}
}

func TestParseFingerprintRejectsMissingMalformedAndNonHex(t *testing.T) {
	for _, value := range []string{"", "00", strings.Repeat("z", 64)} {
		if _, err := ParseFingerprint(value); !errors.Is(err, ErrInvalidFingerprint) {
			t.Errorf("%q: got %v", value, err)
		}
	}
}

func TestVerifyCertificateRejectsMissingPinMalformedDERAndImpostor(t *testing.T) {
	cert, _ := targetCertificate(t, "target.example")
	if err := VerifyCertificate(cert.Certificate[0], Fingerprint{}); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("missing pin: %v", err)
	}
	pin := mustPin(t, cert.Certificate[0])
	if err := VerifyCertificate(nil, pin); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("empty DER: %v", err)
	}
	impostor, _ := targetCertificate(t, "target.example")
	if err := VerifyCertificate(impostor.Certificate[0], pin); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("impostor: %v", err)
	}
}

func TestServerConfigRequiresExplicitRootsAndServerName(t *testing.T) {
	pin := strings.Repeat("0", 64)
	if _, err := ServerConfig(pin, nil, "target.example"); !errors.Is(err, ErrInvalidTLSConfig) {
		t.Fatalf("nil roots: %v", err)
	}
	if _, err := ServerConfig(pin, x509.NewCertPool(), ""); !errors.Is(err, ErrInvalidTLSConfig) {
		t.Fatalf("empty server name: %v", err)
	}
	if _, err := ServerConfig("", x509.NewCertPool(), "target.example"); !errors.Is(err, ErrInvalidFingerprint) {
		t.Fatalf("empty pin: %v", err)
	}
}

func TestServerConfigEnforcesStandardTLSAndPin(t *testing.T) {
	for _, tc := range []struct {
		name          string
		serverName    string
		pinFromTarget bool
		wantErr       bool
	}{
		{name: "matching pin and hostname", serverName: "target.example", pinFromTarget: true},
		{name: "wrong hostname", serverName: "wrong.example", pinFromTarget: true, wantErr: true},
		{name: "wrong pin", serverName: "target.example", pinFromTarget: false, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			serverCert, leaf := targetCertificate(t, "target.example")
			roots := x509.NewCertPool()
			roots.AddCert(leaf)
			pinCert := serverCert.Certificate[0]
			if !tc.pinFromTarget {
				other, _ := targetCertificate(t, "target.example")
				pinCert = other.Certificate[0]
			}
			pin := mustPin(t, pinCert)
			config, err := ServerConfig(hex.EncodeToString(pin.sum[:]), roots, tc.serverName)
			if err != nil {
				t.Fatal(err)
			}
			if config.InsecureSkipVerify {
				t.Fatal("production config disabled standard TLS verification")
			}
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			serverErr := make(chan error, 1)
			go func() {
				conn, err := listener.Accept()
				if err != nil {
					serverErr <- err
					return
				}
				defer conn.Close()
				tlsConn := tls.Server(conn, &tls.Config{Certificates: []tls.Certificate{serverCert}, MinVersion: tls.VersionTLS12})
				serverErr <- tlsConn.Handshake()
			}()
			client, dialErr := tls.Dial("tcp", listener.Addr().String(), config)
			if dialErr == nil {
				_ = client.Close()
			}
			if tc.wantErr && dialErr == nil {
				t.Fatal("invalid target accepted")
			}
			if !tc.wantErr && dialErr != nil {
				t.Fatalf("valid target rejected: %v", dialErr)
			}
		})
	}
}

func mustPin(t *testing.T, der []byte) Fingerprint {
	t.Helper()
	sum := sha256.Sum256(der)
	pin, err := ParseFingerprint(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return pin
}

func targetCertificate(t *testing.T, name string) (tls.Certificate, *x509.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{SerialNumber: big.NewInt(now.UnixNano()), Subject: pkix.Name{CommonName: name}, DNSNames: []string{name}, NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: leaf}, leaf
}

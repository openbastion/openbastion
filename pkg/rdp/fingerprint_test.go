package rdp

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParseCertificateFingerprint(t *testing.T) {
	cert := newTargetCertificate(t)
	want := sha256.Sum256(cert)
	got, err := ParseCertificateFingerprint(hex.EncodeToString(want[:]))
	if err != nil {
		t.Fatal(err)
	}
	if got.sum != want {
		t.Fatalf("parsed fingerprint %x, want %x", got.sum, want)
	}
}

func TestParseCertificateFingerprintRejectsInvalidInput(t *testing.T) {
	for _, input := range []string{"", "00", strings.Repeat("z", 64)} {
		if _, err := ParseCertificateFingerprint(input); !errors.Is(err, ErrInvalidCertificateFingerprint) {
			t.Errorf("ParseCertificateFingerprint(%q) error = %v, want %v", input, err, ErrInvalidCertificateFingerprint)
		}
	}
}

func TestParseCertificateFingerprintAllowsAllZeroDigest(t *testing.T) {
	got, err := ParseCertificateFingerprint(strings.Repeat("0", sha256.Size*2))
	if err != nil {
		t.Fatal(err)
	}
	if !got.set {
		t.Fatal("parsed fingerprint was marked absent")
	}
}

func TestVerifyPinnedCertificate(t *testing.T) {
	leaf := newTargetCertificate(t)
	pin := sha256.Sum256(leaf)
	fingerprint, err := ParseCertificateFingerprint(hex.EncodeToString(pin[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedCertificate(leaf, fingerprint); err != nil {
		t.Fatalf("matching certificate refused: %v", err)
	}
}

func TestVerifyPinnedCertificateRejectsImpostor(t *testing.T) {
	leaf := newTargetCertificate(t)
	impostor := newTargetCertificate(t)
	pin := sha256.Sum256(leaf)
	fingerprint, err := ParseCertificateFingerprint(hex.EncodeToString(pin[:]))
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedCertificate(impostor, fingerprint); !errors.Is(err, ErrTargetCertificateMismatch) {
		t.Fatalf("impostor error = %v, want %v", err, ErrTargetCertificateMismatch)
	}
}

func TestVerifyPinnedCertificateRejectsEmptyDER(t *testing.T) {
	fingerprint := mustFingerprint(t, newTargetCertificate(t))
	if err := VerifyPinnedCertificate(nil, fingerprint); !errors.Is(err, ErrInvalidTargetCertificate) {
		t.Fatalf("empty certificate error = %v, want %v", err, ErrInvalidTargetCertificate)
	}
}

func TestVerifyPinnedCertificateRejectsMissingFingerprint(t *testing.T) {
	if err := VerifyPinnedCertificate(newTargetCertificate(t), CertificateFingerprint{}); !errors.Is(err, ErrInvalidCertificateFingerprint) {
		t.Fatalf("missing fingerprint error = %v, want %v", err, ErrInvalidCertificateFingerprint)
	}
}

func TestVerifyPinnedCertificateRejectsInvalidDER(t *testing.T) {
	fingerprint := mustFingerprint(t, newTargetCertificate(t))
	if err := VerifyPinnedCertificate([]byte("not a certificate"), fingerprint); !errors.Is(err, ErrInvalidTargetCertificate) {
		t.Fatalf("invalid certificate error = %v, want %v", err, ErrInvalidTargetCertificate)
	}
}

func TestVerifyPinnedCertificatePEMUsesLeafFromChain(t *testing.T) {
	leaf := newTargetCertificate(t)
	intermediate := newTargetCertificate(t)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate})...)

	if err := VerifyPinnedCertificatePEM(chain, mustFingerprint(t, leaf)); err != nil {
		t.Fatalf("matching leaf in chain refused: %v", err)
	}
	if err := VerifyPinnedCertificatePEM(chain, mustFingerprint(t, intermediate)); !errors.Is(err, ErrTargetCertificateMismatch) {
		t.Fatalf("intermediate pin error = %v, want %v", err, ErrTargetCertificateMismatch)
	}
}

func TestVerifyPinnedCertificatePEMRejectsMalformedChain(t *testing.T) {
	for _, chain := range [][]byte{
		nil,
		[]byte("not PEM"),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("private")}),
		append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: newTargetCertificate(t)}), []byte("trailing data")...),
	} {
		if err := VerifyPinnedCertificatePEM(chain, mustFingerprint(t, newTargetCertificate(t))); !errors.Is(err, ErrInvalidTargetCertificate) {
			t.Errorf("VerifyPinnedCertificatePEM(%q) error = %v, want %v", chain, err, ErrInvalidTargetCertificate)
		}
	}
}

func TestVerifyPinnedCertificatePEMRejectsOversizedChain(t *testing.T) {
	chain := bytes.Repeat([]byte("x"), MaxCertificateChainBytes+1)
	if err := VerifyPinnedCertificatePEM(chain, mustFingerprint(t, newTargetCertificate(t))); !errors.Is(err, ErrInvalidTargetCertificate) {
		t.Fatalf("oversized chain error = %v, want %v", err, ErrInvalidTargetCertificate)
	}
}

func mustFingerprint(t *testing.T, der []byte) CertificateFingerprint {
	t.Helper()
	sum := sha256.Sum256(der)
	fingerprint, err := ParseCertificateFingerprint(hex.EncodeToString(sum[:]))
	if err != nil {
		t.Fatal(err)
	}
	return fingerprint
}

func newTargetCertificate(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "target.example"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

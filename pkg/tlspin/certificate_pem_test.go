package tlspin

import (
	"bytes"
	"encoding/pem"
	"errors"
	"testing"
)

func TestVerifyCertificatePEMUsesLeafOnly(t *testing.T) {
	leaf, _ := targetCertificate(t, "leaf.example")
	intermediate, _ := targetCertificate(t, "intermediate.example")
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Certificate[0]}), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediate.Certificate[0]})...)
	if err := VerifyCertificatePEM(chain, mustPin(t, leaf.Certificate[0])); err != nil {
		t.Fatalf("leaf pin rejected: %v", err)
	}
	if err := VerifyCertificatePEM(chain, mustPin(t, intermediate.Certificate[0])); !errors.Is(err, ErrFingerprintMismatch) {
		t.Fatalf("intermediate pin accepted: %v", err)
	}
}

func TestVerifyCertificatePEMRejectsMalformedAndOversizedChain(t *testing.T) {
	pin := mustPin(t, func() []byte { cert, _ := targetCertificate(t, "leaf.example"); return cert.Certificate[0] }())
	bad := [][]byte{nil, []byte("not PEM"), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("secret")}), append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), []byte("trailing data")...)}
	for _, chain := range bad {
		if err := VerifyCertificatePEM(chain, pin); !errors.Is(err, ErrInvalidCertificate) {
			t.Errorf("chain %q: got %v", chain, err)
		}
	}
	if err := VerifyCertificatePEM(bytes.Repeat([]byte("x"), MaxCertificateChainBytes+1), pin); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("oversized chain: %v", err)
	}
	if err := VerifyCertificatePEM(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("bad")}), pin); !errors.Is(err, ErrInvalidCertificate) {
		t.Fatalf("invalid DER: %v", err)
	}
}

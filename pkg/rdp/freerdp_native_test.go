//go:build freerdp && cgo

package rdp

import (
	"encoding/pem"
	"errors"
	"testing"
)

func TestFreeRDPCallbackAcceptsPinnedLeaf(t *testing.T) {
	leaf := newTargetCertificate(t)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf})
	verifier := newTestCertificateVerifier(t, mustFingerprint(t, leaf))

	if !verifier.verifyPEM(chain) {
		t.Fatal("FreeRDP certificate callback rejected the pinned leaf")
	}
}

func TestFreeRDPCallbackRejectsImpostorBeforeAuthentication(t *testing.T) {
	pinned := newTargetCertificate(t)
	impostor := newTargetCertificate(t)
	chain := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: impostor})
	verifier := newTestCertificateVerifier(t, mustFingerprint(t, pinned))

	if verifier.verifyPEM(chain) {
		t.Fatal("FreeRDP certificate callback accepted an impostor certificate")
	}
}

func TestFreeRDPCallbackRejectsMalformedCertificate(t *testing.T) {
	leaf := newTargetCertificate(t)
	verifier := newTestCertificateVerifier(t, mustFingerprint(t, leaf))

	for _, chain := range [][]byte{nil, []byte("not PEM")} {
		if verifier.verifyPEM(chain) {
			t.Errorf("FreeRDP certificate callback accepted %q", chain)
		}
	}
}

func TestFreeRDPCallbackRequiresPinnedFingerprint(t *testing.T) {
	if _, err := newCertificateVerifier(CertificateFingerprint{}); !errors.Is(err, ErrInvalidCertificateFingerprint) {
		t.Fatalf("newCertificateVerifier error = %v, want %v", err, ErrInvalidCertificateFingerprint)
	}
}

func newTestCertificateVerifier(t *testing.T, pin CertificateFingerprint) *certificateVerifier {
	t.Helper()
	verifier, err := newCertificateVerifier(pin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(verifier.close)
	return verifier
}

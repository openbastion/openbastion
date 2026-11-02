package tlspin

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	MaxCertificateChainBytes = 1 << 20
	maxCertificatesInChain   = 16
)

// VerifyCertificatePEM validates a bounded PEM chain and pins only its first
// certificate, which is the target's leaf certificate.
func VerifyCertificatePEM(chain []byte, expected Fingerprint) error {
	if !expected.set {
		return ErrInvalidFingerprint
	}
	if len(chain) == 0 || len(chain) > MaxCertificateChainBytes {
		return ErrInvalidCertificate
	}
	remaining := bytes.TrimSpace(chain)
	var leafDER []byte
	for count := 0; len(remaining) > 0; count++ {
		if count == maxCertificatesInChain || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return ErrInvalidCertificate
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrInvalidCertificate
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidCertificate, err)
		}
		if count == 0 {
			leafDER = certificate.Raw
		}
		remaining = bytes.TrimSpace(rest)
	}
	if len(leafDER) == 0 {
		return ErrInvalidCertificate
	}
	return VerifyCertificate(leafDER, expected)
}

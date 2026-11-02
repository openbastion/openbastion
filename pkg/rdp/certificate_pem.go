package rdp

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

// MaxCertificateChainBytes bounds certificate data passed by the native TLS callback.
const MaxCertificateChainBytes = 1 << 20

const maxCertificatesInChain = 16

// VerifyPinnedCertificatePEM verifies the first certificate in a PEM chain as the leaf.
func VerifyPinnedCertificatePEM(chain []byte, expected CertificateFingerprint) error {
	if !expected.set {
		return ErrInvalidCertificateFingerprint
	}
	if len(chain) == 0 || len(chain) > MaxCertificateChainBytes {
		return ErrInvalidTargetCertificate
	}

	remaining := bytes.TrimSpace(chain)
	var leafDER []byte
	for count := 0; len(remaining) > 0; count++ {
		if count == maxCertificatesInChain || !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return ErrInvalidTargetCertificate
		}
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 {
			return ErrInvalidTargetCertificate
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrInvalidTargetCertificate, err)
		}
		if count == 0 {
			leafDER = certificate.Raw
		}
		remaining = bytes.TrimSpace(rest)
	}
	if len(leafDER) == 0 {
		return ErrInvalidTargetCertificate
	}
	return VerifyPinnedCertificate(leafDER, expected)
}

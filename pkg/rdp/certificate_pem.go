package rdp

import "github.com/openbastion/openbastion/pkg/tlspin"

// MaxCertificateChainBytes is retained for compatibility; pinning is implemented by pkg/tlspin.
const MaxCertificateChainBytes = tlspin.MaxCertificateChainBytes

// Deprecated: use tlspin.VerifyCertificatePEM.
func VerifyPinnedCertificatePEM(chain []byte, expected CertificateFingerprint) error {
	return tlspin.VerifyCertificatePEM(chain, expected)
}

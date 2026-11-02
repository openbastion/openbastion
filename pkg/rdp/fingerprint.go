package rdp

import "github.com/openbastion/openbastion/pkg/tlspin"

// Deprecated: certificate pinning primitives live in pkg/tlspin.
type CertificateFingerprint = tlspin.Fingerprint

var (
	ErrInvalidCertificateFingerprint = tlspin.ErrInvalidFingerprint
	ErrInvalidTargetCertificate      = tlspin.ErrInvalidCertificate
	ErrTargetCertificateMismatch     = tlspin.ErrFingerprintMismatch
)

// Deprecated: use tlspin.ParseFingerprint.
func ParseCertificateFingerprint(value string) (CertificateFingerprint, error) {
	return tlspin.ParseFingerprint(value)
}

// Deprecated: use tlspin.VerifyCertificate.
func VerifyPinnedCertificate(der []byte, expected CertificateFingerprint) error {
	return tlspin.VerifyCertificate(der, expected)
}

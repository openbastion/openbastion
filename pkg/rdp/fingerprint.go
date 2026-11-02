package rdp

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

var (
	// ErrInvalidCertificateFingerprint indicates a missing or malformed SHA-256 pin.
	ErrInvalidCertificateFingerprint = errors.New("invalid RDP certificate fingerprint")
	// ErrInvalidTargetCertificate indicates that the target certificate cannot be parsed.
	ErrInvalidTargetCertificate = errors.New("invalid RDP target certificate")
	// ErrTargetCertificateMismatch indicates that the parsed target certificate differs from its pin.
	ErrTargetCertificateMismatch = errors.New("RDP target certificate does not match the pinned fingerprint")
)

// CertificateFingerprint is the SHA-256 digest of a target's leaf certificate.
type CertificateFingerprint struct {
	sum [sha256.Size]byte
	set bool
}

// ParseCertificateFingerprint parses a 64-digit hexadecimal SHA-256 digest.
func ParseCertificateFingerprint(value string) (CertificateFingerprint, error) {
	var fingerprint CertificateFingerprint
	if len(value) != hex.EncodedLen(sha256.Size) {
		return fingerprint, ErrInvalidCertificateFingerprint
	}
	if _, err := hex.Decode(fingerprint.sum[:], []byte(value)); err != nil {
		return CertificateFingerprint{}, ErrInvalidCertificateFingerprint
	}
	fingerprint.set = true
	return fingerprint, nil
}

// VerifyPinnedCertificate checks DER syntax and compares the leaf digest in constant time.
func VerifyPinnedCertificate(der []byte, expected CertificateFingerprint) error {
	if !expected.set {
		return ErrInvalidCertificateFingerprint
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return ErrInvalidTargetCertificate
	}
	actual := sha256.Sum256(der)
	if subtle.ConstantTimeCompare(actual[:], expected.sum[:]) != 1 {
		return ErrTargetCertificateMismatch
	}
	return nil
}

package rdp

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

var (
	ErrInvalidCertificateFingerprint = errors.New("invalid RDP certificate fingerprint")
	ErrInvalidTargetCertificate      = errors.New("invalid RDP target certificate")
	ErrTargetCertificateMismatch     = errors.New("RDP target certificate does not match the pinned fingerprint")
)

type CertificateFingerprint struct {
	sum [sha256.Size]byte
	set bool
}

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

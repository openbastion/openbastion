// Package tlspin provides certificate pinning for outbound target TLS connections.
package tlspin

import (
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
)

var (
	ErrInvalidFingerprint  = errors.New("invalid TLS certificate fingerprint")
	ErrInvalidCertificate  = errors.New("invalid TLS target certificate")
	ErrFingerprintMismatch = errors.New("TLS target certificate fingerprint mismatch")
)

// Fingerprint is a validated SHA-256 digest of a target's leaf certificate.
// Its fields are private so callers cannot construct a trusted pin accidentally.
type Fingerprint struct {
	sum [sha256.Size]byte
	set bool
}

// ParseFingerprint accepts exactly 64 hexadecimal characters.
func ParseFingerprint(value string) (Fingerprint, error) {
	var pin Fingerprint
	if len(value) != hex.EncodedLen(sha256.Size) {
		return pin, ErrInvalidFingerprint
	}
	if _, err := hex.Decode(pin.sum[:], []byte(value)); err != nil {
		return Fingerprint{}, ErrInvalidFingerprint
	}
	pin.set = true
	return pin, nil
}

// VerifyCertificate parses DER and compares its SHA-256 digest in constant time.
func VerifyCertificate(der []byte, expected Fingerprint) error {
	if !expected.set {
		return ErrInvalidFingerprint
	}
	if _, err := x509.ParseCertificate(der); err != nil {
		return ErrInvalidCertificate
	}
	actual := sha256.Sum256(der)
	if subtle.ConstantTimeCompare(actual[:], expected.sum[:]) != 1 {
		return ErrFingerprintMismatch
	}
	return nil
}

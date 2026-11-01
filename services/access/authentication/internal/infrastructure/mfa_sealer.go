package infrastructure

// The TOTP secrets at rest (ADR-0062): AES-256-GCM under MFA_SECRET_KEY_HEX, kept outside the
// database; the account's id is the associated data, so that a sealed secret copied onto another
// account does not open.

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
)

const mfaSealVersion = 1

// MFASealer is an application.SecretSealer.
type MFASealer struct{ aead cipher.AEAD }

// NewMFASealer takes the key as 64 hex digits; its errors never repeat it.
func NewMFASealer(keyHex string) (*MFASealer, error) {
	key, err := hex.DecodeString(keyHex)
	if err != nil || len(key) != 32 {
		return nil, errors.New("MFA_SECRET_KEY_HEX must be 64 hex digits (32 bytes; `openssl rand -hex 32`)")
	}
	block, _ := aes.NewCipher(key)
	aead, _ := cipher.NewGCM(block)
	return &MFASealer{aead: aead}, nil
}

func mfaAAD(userID string) []byte { return []byte("openbastion.mfa.totp.v1\x00" + userID) }

// Seal returns version ‖ nonce ‖ ciphertext.
func (m *MFASealer) Seal(userID string, secret []byte) ([]byte, error) {
	nonce := make([]byte, m.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append([]byte{mfaSealVersion}, nonce...)
	return m.aead.Seal(out, nonce, secret, mfaAAD(userID)), nil
}

// Open refuses a sealed secret of another key, of another account, or altered.
func (m *MFASealer) Open(userID string, sealed []byte) ([]byte, error) {
	n := m.aead.NonceSize()
	if len(sealed) < 1+n || sealed[0] != mfaSealVersion {
		return nil, errors.New("not a sealed TOTP secret")
	}
	secret, err := m.aead.Open(nil, sealed[1:1+n], sealed[1+n:], mfaAAD(userID))
	if err != nil {
		return nil, errors.New("the TOTP secret does not open with this key for this account")
	}
	return secret, nil
}

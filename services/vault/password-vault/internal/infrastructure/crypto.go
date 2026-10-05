package infrastructure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
)

// LocalKMS stands in for an external KMS/HSM (Guide Sécurité §6,
// OpenBastion_06_Modele_Donnees.md §3: "encryption_key_id... référence à
// la clé KMS/HSM, pas la clé elle-même"). It exists so this service runs
// end-to-end without a real KMS dependency; swapping it for a real KMS
// client touches only this file — application/ depends on the Encryptor
// interface, not on LocalKMS directly.
type LocalKMS struct {
	keyID string
	key   [32]byte // AES-256
}

func NewLocalKMS() (*LocalKMS, error) {
	var key [32]byte
	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return nil, err
	}
	return &LocalKMS{keyID: "local-dev-key-v1", key: key}, nil
}

func (k *LocalKMS) KeyID() string { return k.keyID }

// Seal encrypts plaintext with AES-256-GCM. The nonce is prepended to the
// ciphertext so Open needs only the key, not separate nonce storage.
func (k *LocalKMS) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func (k *LocalKMS) Open(ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(k.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ct := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, nil)
}

package infrastructure

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

type LocalKEK struct {
	keyID string
	key   [32]byte
}

func NewLocalKEKFromHexKey(value string) (*LocalKEK, error) {
	if value == "" {
		return nil, errors.New("KMS_KEY_HEX: no key given")
	}
	raw, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("KMS_KEY_HEX: invalid hex encoding: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("KMS_KEY_HEX: expected 32 bytes for AES-256, got %d", len(raw))
	}
	k := &LocalKEK{keyID: "local-video-recorder-kek-v1"}
	copy(k.key[:], raw)
	return k, nil
}

func (k *LocalKEK) KeyID() string { return k.keyID }

func (k *LocalKEK) Wrap(_ context.Context, dek, aad []byte) ([]byte, error) {
	return sealKey(k.key[:], dek, aad)
}

func (k *LocalKEK) Unwrap(_ context.Context, wrapped, aad []byte) ([]byte, error) {
	return openKey(k.key[:], wrapped, aad)
}

func (k *LocalKEK) Ready(context.Context) error { return nil }

func sealKey(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := keyGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func openKey(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := keyGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("wrapped key is too short")
	}
	return gcm.Open(nil, sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():], aad)
}

func keyGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

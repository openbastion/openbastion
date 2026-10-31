package infrastructure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
)

// LocalKMS stands in for an external KMS/HSM (docs/security/secrets-management.md,
// docs/architecture/data-architecture.md §3: "encryption_key_id... référence à
// la clé KMS/HSM, pas la clé elle-même"). It exists so this service runs
// end-to-end without a real KMS dependency; swapping it for a real KMS
// client touches only this file — application/ depends on the Encryptor
// interface, not on LocalKMS directly.
type LocalKMS struct {
	keyID string
	key   [32]byte // AES-256
}

// NewLocalKMS generates a fresh, random, in-process-only key — see
// NewLocalKMSFromHexKey's doc comment for why this is unsafe to use
// whenever sealed material is expected to outlive the process (i.e.
// whenever DATABASE_URL is set; cmd/password-vault/main.go enforces
// this). Kept for callers that only ever need a single process's
// lifetime — the in-memory store, and every existing test/example that
// predates PostgreSQL support.
func NewLocalKMS() (*LocalKMS, error) {
	return NewLocalKMSFromHexKey("")
}

// NewLocalKMSFromHexKey builds a LocalKMS from a hex-encoded 32-byte
// (AES-256) key, typically KMS_KEY_HEX (cmd/password-vault/main.go).
//
// An empty hexKey generates a fresh random key instead, exactly like
// NewLocalKMS did unconditionally before this increment — fine for a
// single process's lifetime (the in-memory store, tests), but any
// material it seals becomes permanently unreadable the moment that
// process exits: a restarted process would generate ANOTHER random key
// with no relation to the first, so Open would fail GCM authentication
// on every row the previous process wrote. This was a real, latent bug
// in this increment's own PostgreSQL support until caught by
// TestPostgresFlow_AccountSurvivesPasswordVaultProcessRestart actually
// restarting a second process — see NOTES_SANDBOX.md. A persistent
// deployment (DATABASE_URL set) MUST supply KMS_KEY_HEX, generated once
// (e.g. `openssl rand -hex 32`) and kept outside the database — exactly
// the separation docs/architecture/data-architecture.md §3 already documents for encryption_key_id. A
// real external KMS/HSM client would replace this file entirely; this
// is still only ever a stand-in for one.
func NewLocalKMSFromHexKey(hexKey string) (*LocalKMS, error) {
	if hexKey == "" {
		var key [32]byte
		if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
			return nil, err
		}
		return &LocalKMS{keyID: "local-dev-key-v1", key: key}, nil
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("KMS_KEY_HEX: invalid hex encoding: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("KMS_KEY_HEX: expected 32 bytes (64 hex characters) for AES-256, got %d bytes", len(raw))
	}
	var key [32]byte
	copy(key[:], raw)
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

package infrastructure

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"time"
)

// Envelope encryption for recorded commands.
//
// Each session gets its own random 256-bit data key (DEK). Every command of
// that session is sealed under the DEK with AES-256-GCM, and the DEK itself is
// stored only wrapped under the key-encryption key (KEK) held by a KeyWrapper.
// The database therefore never contains a command, nor a usable key, in the
// clear: reading a recording needs both the rows and the KEK.
//
// Why a DEK per session rather than sealing everything under the KEK:
//   - GCM with random 96-bit nonces is safe only for a bounded number of
//     messages per key; one key per session keeps each key far below that
//     however many recordings accumulate.
//   - A recording can be made permanently unreadable by destroying its one
//     wrapped DEK (crypto-shredding) without touching the rows — the basis
//     for a retention policy, which is not built yet.
//
// What the ciphertext is bound to. Every sealed command carries its session id
// and its timestamp as GCM additional data, and the wrapped DEK carries its
// session id: moving a row to another session, or editing its timestamp,
// makes decryption fail instead of silently producing a different, valid
// replay. What it does NOT protect against is a database-level attacker
// deleting rows or reordering them while leaving each row intact (rows are
// authenticated one by one, not as a chain) — the audit log's hash chain is
// the mechanism for that in this project, and recordings do not have one yet.

// KeyWrapper wraps and unwraps data keys under the key-encryption key. It is
// the seam where a real KMS/HSM client replaces LocalKEK; nothing else in the
// service knows how keys are protected.
type KeyWrapper interface {
	// KeyID names the KEK, and is stored next to every wrapped DEK so a
	// future rotation can tell which KEK a row needs.
	KeyID() string
	Wrap(dek, aad []byte) ([]byte, error)
	Unwrap(wrapped, aad []byte) ([]byte, error)
}

// LocalKEK stands in for an external KMS/HSM, exactly as the Password Vault's
// LocalKMS does (Guide Sécurité §6). Swapping it for a real client touches
// only this file.
type LocalKEK struct {
	keyID string
	key   [32]byte
}

// NewLocalKEKFromHexKey builds a LocalKEK from a hex-encoded 32-byte key,
// KMS_KEY_HEX in cmd/command-recorder.
//
// Unlike the Vault's equivalent there is deliberately NO empty-key fallback to
// a random per-process key: that fallback exists there for the in-memory
// store, and is the source of a bug this project already paid for — material
// sealed under a random key is unreadable after a restart. Here the key is
// only needed when PostgreSQL is used, where the data must outlive the
// process, so an absent or malformed key is simply an error.
func NewLocalKEKFromHexKey(hexKey string) (*LocalKEK, error) {
	if hexKey == "" {
		return nil, errors.New("KMS_KEY_HEX: no key given")
	}
	raw, err := hex.DecodeString(hexKey)
	if err != nil {
		return nil, fmt.Errorf("KMS_KEY_HEX: invalid hex encoding: %w", err)
	}
	if len(raw) != 32 {
		return nil, fmt.Errorf("KMS_KEY_HEX: expected 32 bytes (64 hex characters) for AES-256, got %d bytes", len(raw))
	}
	k := &LocalKEK{keyID: "local-recorder-kek-v1"}
	copy(k.key[:], raw)
	return k, nil
}

func (k *LocalKEK) KeyID() string { return k.keyID }

func (k *LocalKEK) Wrap(dek, aad []byte) ([]byte, error) { return gcmSeal(k.key[:], dek, aad) }
func (k *LocalKEK) Unwrap(wrapped, aad []byte) ([]byte, error) {
	return gcmOpen(k.key[:], wrapped, aad)
}

// newDEK returns a fresh random 256-bit data key.
func newDEK() ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	return dek, nil
}

// zero overwrites key material once it is no longer needed. Best effort — Go
// gives no guarantee about copies the runtime may have made — but a data key
// should not sit in memory longer than the request that needed it.
func zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// dekAAD binds a wrapped DEK to the KEK and the session it belongs to. The
// KEK id is length-prefixed so the two fields cannot be shifted into each other
// (("a|b","c") and ("a","b|c") would otherwise produce the same bytes); the
// session id comes last, so it needs no delimiter of its own.
func dekAAD(kekID, sessionID string) []byte {
	return []byte("openbastion/recorder/dek/v1|" + strconv.Itoa(len(kekID)) + "|" + kekID + "|" + sessionID)
}

// entryAAD binds a sealed command to its session and timestamp. The
// timestamp is taken at microsecond precision — what PostgreSQL stores — so
// the value used to seal is the value read back to open; RecorderService
// truncates timestamps to this precision before they reach the store.
func entryAAD(sessionID string, ts time.Time) []byte {
	return []byte("openbastion/recorder/entry/v1|" + sessionID + "|" + strconv.FormatInt(ts.UnixMicro(), 10))
}

func sealCommand(dek []byte, sessionID string, ts time.Time, command string) ([]byte, error) {
	return gcmSeal(dek, []byte(command), entryAAD(sessionID, ts))
}

func openCommand(dek []byte, sessionID string, ts time.Time, sealed []byte) (string, error) {
	plain, err := gcmOpen(dek, sealed, entryAAD(sessionID, ts))
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// gcmSeal encrypts with AES-256-GCM under a fresh random nonce, which is
// prepended to the ciphertext so opening needs only the key and the AAD.
func gcmSeal(key, plaintext, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, aad), nil
}

func gcmOpen(key, sealed, aad []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize()+gcm.Overhead() {
		return nil, errors.New("sealed value too short")
	}
	nonce, ct := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ct, aad)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

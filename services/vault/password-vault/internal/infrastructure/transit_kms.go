package infrastructure

// The Vault's keys kept by Transit (ADR-0049): an envelope per secret, the data key wrapped by
// a key that never leaves the Transit server; and a keyring that opens each version with the key
// it names, so that what was sealed before stays readable.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/openbastion/openbastion/pkg/transit"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// transitEnvelopeAAD binds every data key, and every secret sealed under one, to this service:
// a wrapped key taken from elsewhere — another service using the same Transit key — does not open.
var transitEnvelopeAAD = []byte("openbastion.password-vault.secret.v1")

// envelopeMagic starts every sealed secret: a format that can be told from any other.
var envelopeMagic = []byte("OBT1")

// Wrapper is what TransitKMS needs of Transit: pkg/transit.Client.
type Wrapper interface {
	KeyID() string
	Encrypt(ctx context.Context, plaintext, aad []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string, aad []byte) ([]byte, error)
}

var _ Wrapper = (*transit.Client)(nil)

// TransitKMS seals each secret under a fresh 256-bit data key (AES-256-GCM), and the data key under
// the Transit key: the secret itself never leaves this process; the Transit key never leaves Transit.
type TransitKMS struct{ w Wrapper }

// NewTransitKMS returns an encryptor over w.
func NewTransitKMS(w Wrapper) *TransitKMS { return &TransitKMS{w: w} }

func (k *TransitKMS) KeyID() string { return k.w.KeyID() }

// Seal returns "OBT1" | length of the wrapped key (2 bytes) | wrapped key | nonce | ciphertext.
func (k *TransitKMS) Seal(plaintext []byte) ([]byte, error) {
	dek := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, err
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	wrapped, err := k.w.Encrypt(context.Background(), dek, transitEnvelopeAAD)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", domain.ErrKeysUnavailable, err)
	}
	if len(wrapped) > 0xffff {
		return nil, errors.New("transit: the wrapped key is too long")
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := append([]byte(nil), envelopeMagic...)
	out = binary.BigEndian.AppendUint16(out, uint16(len(wrapped)))
	out = append(out, wrapped...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plaintext, transitEnvelopeAAD), nil
}

// Open unwraps the data key with Transit, then opens the secret.
func (k *TransitKMS) Open(keyID string, sealed []byte) ([]byte, error) {
	if keyID != k.KeyID() {
		return nil, fmt.Errorf("%w: %q (this key is %q)", ErrUnknownKey, keyID, k.KeyID())
	}
	rest, ok := cutPrefix(sealed, envelopeMagic)
	if !ok || len(rest) < 2 {
		return nil, errors.New("not a Transit envelope")
	}
	n := int(binary.BigEndian.Uint16(rest))
	rest = rest[2:]
	if len(rest) < n {
		return nil, errors.New("a truncated Transit envelope")
	}
	wrapped, rest := string(rest[:n]), rest[n:]
	dek, err := k.w.Decrypt(context.Background(), wrapped, transitEnvelopeAAD)
	if err != nil {
		// Transit unreachable or refusing, or a wrapped key that is not its own: the secret
		// cannot be opened now; it is not a refusal of the caller.
		return nil, fmt.Errorf("%w: %v", domain.ErrKeysUnavailable, err)
	}
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(rest) < gcm.NonceSize() {
		return nil, errors.New("a truncated Transit envelope")
	}
	return gcm.Open(nil, rest[:gcm.NonceSize()], rest[gcm.NonceSize():], transitEnvelopeAAD)
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, errors.New("a data key must be 32 bytes")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func cutPrefix(b, prefix []byte) ([]byte, bool) {
	if len(b) < len(prefix) || string(b[:len(prefix)]) != string(prefix) {
		return nil, false
	}
	return b[len(prefix):], true
}

// Sealer is one key the keyring can open with: the shape of application.Encryptor.
type Sealer interface {
	KeyID() string
	Seal(plaintext []byte) ([]byte, error)
	Open(keyID string, ciphertext []byte) ([]byte, error)
}

// Keyring seals with its current key and opens each version with the key the version names
// (ADR-0049). The previous keys are for reading only: what was sealed before stays readable,
// nothing new is sealed under them.
type Keyring struct {
	current  Sealer
	previous map[string]Sealer
}

// NewKeyring returns a keyring; previous keys may not share an id with the current one.
func NewKeyring(current Sealer, previous ...Sealer) (*Keyring, error) {
	r := &Keyring{current: current, previous: map[string]Sealer{}}
	for _, p := range previous {
		if p.KeyID() == current.KeyID() || r.previous[p.KeyID()] != nil {
			return nil, fmt.Errorf("the key %q is given twice", p.KeyID())
		}
		r.previous[p.KeyID()] = p
	}
	return r, nil
}

func (r *Keyring) KeyID() string                         { return r.current.KeyID() }
func (r *Keyring) Seal(plaintext []byte) ([]byte, error) { return r.current.Seal(plaintext) }

// Open opens with the key keyID names; a key the keyring does not hold is ErrUnknownKey.
func (r *Keyring) Open(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID == r.current.KeyID() {
		return r.current.Open(keyID, ciphertext)
	}
	if p, ok := r.previous[keyID]; ok {
		return p.Open(keyID, ciphertext)
	}
	return nil, fmt.Errorf("%w: %q", ErrUnknownKey, keyID)
}

// PreviousKeyIDs lists the keys held for reading only, for the start-up log.
func (r *Keyring) PreviousKeyIDs() []string {
	var ids []string
	for id := range r.previous {
		ids = append(ids, id)
	}
	return ids
}

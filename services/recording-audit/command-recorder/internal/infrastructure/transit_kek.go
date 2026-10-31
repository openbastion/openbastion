package infrastructure

import (
	"context"

	"github.com/openbastion/openbastion/pkg/transit"
)

// TransitWrapper is what TransitKEK needs of Transit: pkg/transit.Client.
type TransitWrapper interface {
	KeyID() string
	Encrypt(ctx context.Context, plaintext, aad []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string, aad []byte) ([]byte, error)
}

var _ TransitWrapper = (*transit.Client)(nil)

// TransitKEK is the KeyWrapper whose key-encryption key lives in Transit and never leaves it
// (ADR-0049): each session's data key is wrapped there, bound to dekAAD — the key id and the
// session — exactly as LocalKEK binds it.
type TransitKEK struct{ w TransitWrapper }

// NewTransitKEK returns a KeyWrapper over w.
func NewTransitKEK(w TransitWrapper) *TransitKEK { return &TransitKEK{w: w} }

func (k *TransitKEK) KeyID() string { return k.w.KeyID() }

func (k *TransitKEK) Wrap(dek, aad []byte) ([]byte, error) {
	ct, err := k.w.Encrypt(context.Background(), dek, aad)
	if err != nil {
		return nil, err
	}
	return []byte(ct), nil
}

func (k *TransitKEK) Unwrap(wrapped, aad []byte) ([]byte, error) {
	return k.w.Decrypt(context.Background(), string(wrapped), aad)
}

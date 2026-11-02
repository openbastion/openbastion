package infrastructure

import (
	"context"
	"errors"

	"github.com/openbastion/openbastion/pkg/transit"
)

type TransitWrapper interface {
	KeyID() string
	Encrypt(ctx context.Context, plaintext, aad []byte) (string, error)
	Decrypt(ctx context.Context, ciphertext string, aad []byte) ([]byte, error)
	Probe(ctx context.Context) error
}

type TransitKEK struct{ client TransitWrapper }

func NewTransitKEK(client TransitWrapper) *TransitKEK { return &TransitKEK{client: client} }

func (k *TransitKEK) KeyID() string { return k.client.KeyID() }

func (k *TransitKEK) Wrap(ctx context.Context, dek, aad []byte) ([]byte, error) {
	ciphertext, err := k.client.Encrypt(ctx, dek, aad)
	return []byte(ciphertext), err
}

func (k *TransitKEK) Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error) {
	return k.client.Decrypt(ctx, string(wrapped), aad)
}

func (k *TransitKEK) Ready(ctx context.Context) error {
	if k.client == nil {
		return errors.New("Transit client is missing")
	}
	return k.client.Probe(ctx)
}

var _ TransitWrapper = (*transit.Client)(nil)

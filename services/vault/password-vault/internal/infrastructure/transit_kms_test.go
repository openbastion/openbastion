package infrastructure_test

// ADR-0049: a secret is sealed under a fresh data key, the data key wrapped by Transit; Transit
// never sees the secret; each version opens with the key it names, and what was sealed under the
// local key stays readable once Transit is the current key.

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

// fakeWrapper plays Transit: AES-GCM under its own key, aad bound; it keeps every plaintext it
// was given to wrap.
type fakeWrapper struct {
	gcm  cipher.AEAD
	mu   sync.Mutex
	saw  [][]byte
	aads [][]byte
	down bool
}

func newFakeWrapper() *fakeWrapper {
	key := make([]byte, 32)
	_, _ = rand.Read(key)
	b, _ := aes.NewCipher(key)
	g, _ := cipher.NewGCM(b)
	return &fakeWrapper{gcm: g}
}

func (f *fakeWrapper) KeyID() string { return "transit:transit/vault" }

func (f *fakeWrapper) Encrypt(_ context.Context, p, aad []byte) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return "", errors.New("transit encrypt at http://127.0.0.1:8200: connection refused")
	}
	f.saw, f.aads = append(f.saw, append([]byte(nil), p...)), append(f.aads, append([]byte(nil), aad...))
	nonce := make([]byte, f.gcm.NonceSize())
	_, _ = rand.Read(nonce)
	return "vault:v1:" + base64.StdEncoding.EncodeToString(f.gcm.Seal(nonce, nonce, p, aad)), nil
}

func (f *fakeWrapper) Decrypt(_ context.Context, ct string, aad []byte) ([]byte, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.down {
		return nil, errors.New("transit decrypt at http://127.0.0.1:8200: connection refused")
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
	if err != nil || len(raw) < f.gcm.NonceSize() {
		return nil, errors.New("not a ciphertext")
	}
	return f.gcm.Open(nil, raw[:f.gcm.NonceSize()], raw[f.gcm.NonceSize():], aad)
}

func TestTransitKMS_TheSecretStaysHere_OnlyAFreshDataKeyGoesToTransit(t *testing.T) {
	w := newFakeWrapper()
	k := infrastructure.NewTransitKMS(w)
	secret := []byte("the-root-password-of-the-target")
	a, err := k.Seal(secret)
	if err != nil {
		t.Fatal(err)
	}
	b, _ := k.Seal(secret)
	if bytes.Contains(a, secret) || bytes.Equal(a, b) {
		t.Fatal("the sealed secret shows the secret, or two seals are the same")
	}
	got, err := k.Open(k.KeyID(), a)
	if err != nil || !bytes.Equal(got, secret) {
		t.Fatalf("Open = %q, %v", got, err)
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if len(w.saw) != 2 || bytes.Equal(w.saw[0], w.saw[1]) {
		t.Fatalf("Transit was given %d keys, the same twice or not: each secret has its own data key", len(w.saw))
	}
	for i, p := range w.saw {
		if len(p) != 32 || bytes.Contains(p, secret) || len(w.aads[i]) == 0 {
			t.Fatalf("Transit was given %q (aad %q): a data key of 32 bytes, bound to associated data, and never the secret", p, w.aads[i])
		}
	}
}

func TestTransitKMS_ATamperedOrForeignEnvelopeDoesNotOpen(t *testing.T) {
	k := infrastructure.NewTransitKMS(newFakeWrapper())
	sealed, _ := k.Seal([]byte("s3cr3t"))
	flip := func(i int) []byte { c := append([]byte(nil), sealed...); c[i] ^= 1; return c }
	for name, c := range map[string][]byte{
		"a byte of the secret changed": flip(len(sealed) - 1),
		"a byte of the nonce changed":  flip(len(sealed) - 20),
		"a byte of the wrapped key":    flip(10),
		"the magic changed":            flip(0),
		"truncated":                    sealed[:len(sealed)/2],
		"empty":                        nil,
		"another Transit's envelope":   mustSeal(t, infrastructure.NewTransitKMS(newFakeWrapper()), "s3cr3t"),
	} {
		if _, err := k.Open(k.KeyID(), c); err == nil {
			t.Fatalf("%s: opened", name)
		}
	}
	if _, err := k.Open("local-dev-key-v1", sealed); !errors.Is(err, infrastructure.ErrUnknownKey) {
		t.Fatalf("a version naming another key: %v, want ErrUnknownKey", err)
	}
}

func mustSeal(t *testing.T, k *infrastructure.TransitKMS, s string) []byte {
	t.Helper()
	b, err := k.Seal([]byte(s))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTransitKMS_TransitDown_NothingIsSealedNorOpened(t *testing.T) {
	w := newFakeWrapper()
	k := infrastructure.NewTransitKMS(w)
	sealed, _ := k.Seal([]byte("s3cr3t"))
	w.down = true
	if _, err := k.Seal([]byte("other")); !errors.Is(err, domain.ErrKeysUnavailable) {
		t.Fatalf("a seal with Transit down: %v, want ErrKeysUnavailable", err)
	}
	if _, err := k.Open(k.KeyID(), sealed); !errors.Is(err, domain.ErrKeysUnavailable) {
		t.Fatalf("an open with Transit down: %v, want ErrKeysUnavailable", err)
	}
}

func TestKeyring_SealsWithTheCurrentKey_OpensEachVersionWithTheKeyItNames(t *testing.T) {
	local, err := infrastructure.NewLocalKMSFromHexKey(strings.Repeat("ab", 32))
	if err != nil {
		t.Fatal(err)
	}
	before, _ := local.Seal([]byte("sealed-before-the-switch"))
	tr := infrastructure.NewTransitKMS(newFakeWrapper())
	ring, err := infrastructure.NewKeyring(tr, local)
	if err != nil {
		t.Fatal(err)
	}
	if ring.KeyID() != tr.KeyID() {
		t.Fatalf("the ring's key is %q, want the current one", ring.KeyID())
	}
	after, _ := ring.Seal([]byte("sealed-after"))
	if got, err := ring.Open(local.KeyID(), before); err != nil || string(got) != "sealed-before-the-switch" {
		t.Fatalf("a secret sealed under the previous key: %q, %v", got, err)
	}
	if got, err := ring.Open(tr.KeyID(), after); err != nil || string(got) != "sealed-after" {
		t.Fatalf("a secret sealed under the current key: %q, %v", got, err)
	}
	if _, err := local.Open(local.KeyID(), after); err == nil {
		t.Fatal("a new secret was sealed under the previous key")
	}
	if _, err := ring.Open("transit:transit/another", after); !errors.Is(err, infrastructure.ErrUnknownKey) {
		t.Fatalf("a key the ring does not hold: %v, want ErrUnknownKey", err)
	}
	// Without the previous key, what was sealed before is refused, by name, not guessed.
	only, _ := infrastructure.NewKeyring(tr)
	if _, err := only.Open(local.KeyID(), before); !errors.Is(err, infrastructure.ErrUnknownKey) {
		t.Fatalf("without the previous key: %v, want ErrUnknownKey", err)
	}
	if _, err := infrastructure.NewKeyring(tr, tr); err == nil {
		t.Fatal("a key given twice was accepted")
	}
}

func TestLocalKMS_AVersionNamingAnotherKeyIsRefused(t *testing.T) {
	local, _ := infrastructure.NewLocalKMSFromHexKey(strings.Repeat("ab", 32))
	sealed, _ := local.Seal([]byte("s3cr3t"))
	if _, err := local.Open("transit:transit/vault", sealed); !errors.Is(err, infrastructure.ErrUnknownKey) || !errors.Is(err, domain.ErrKeysUnavailable) {
		t.Fatalf("%v, want ErrUnknownKey, which is ErrKeysUnavailable", err)
	}
}

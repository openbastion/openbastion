package application_test

// ADR-0055: what an earlier key still protects is re-sealed under the current one, audited first,
// a batch at a time, without changing any secret, and never over what was written meanwhile.

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

// playedTransit wraps for real under its own key, as Transit does.
type playedTransit struct{ gcm cipher.AEAD }

func newPlayedTransit() *playedTransit {
	k := make([]byte, 32)
	_, _ = rand.Read(k)
	b, _ := aes.NewCipher(k)
	g, _ := cipher.NewGCM(b)
	return &playedTransit{gcm: g}
}
func (p *playedTransit) KeyID() string { return "transit:transit/vault" }
func (p *playedTransit) Encrypt(_ context.Context, pt, aad []byte) (string, error) {
	n := make([]byte, p.gcm.NonceSize())
	_, _ = rand.Read(n)
	return "vault:v1:" + base64.StdEncoding.EncodeToString(p.gcm.Seal(n, n, pt, aad)), nil
}
func (p *playedTransit) Decrypt(_ context.Context, ct string, aad []byte) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(ct, "vault:v1:"))
	if err != nil || len(raw) < p.gcm.NonceSize() {
		return nil, errors.New("not a ciphertext")
	}
	return p.gcm.Open(nil, raw[:p.gcm.NonceSize()], raw[p.gcm.NonceSize():], aad)
}

// switched is a Vault that sealed under the local key, then got Transit as its current key.
func switched(t *testing.T, accounts int) (*application.VaultService, *infrastructure.InMemoryStore, *fakeAudit, string) {
	t.Helper()
	local, _ := infrastructure.NewLocalKMSFromHexKey(strings.Repeat("ab", 32))
	store := infrastructure.NewInMemoryStore()
	before := application.NewVaultService(store, store, store, local, &fakeAuthz{allowed: true})
	ctx := context.Background()
	for i := 0; i < accounts; i++ {
		id := fmt.Sprintf("acc%02d", i)
		if err := onboardTest(before, ctx, adminRoles, id, id, "root", host, "ssh", domain.RotationManual, []byte("secret-"+id)); err != nil {
			t.Fatal(err)
		}
	}
	ring, err := infrastructure.NewKeyring(infrastructure.NewTransitKMS(newPlayedTransit()), local)
	if err != nil {
		t.Fatal(err)
	}
	audit := &fakeAudit{}
	svc := application.NewVaultService(store, store, store, ring, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), audit)
	return svc, store, audit, local.KeyID()
}

func keyOf(t *testing.T, store *infrastructure.InMemoryStore, account string) string {
	t.Helper()
	v, err := store.CurrentVersion(context.Background(), account)
	if err != nil {
		t.Fatal(err)
	}
	return v.EncryptionKeyID
}

func TestRewrapDue_WhatTheLocalKeyProtectsGoesUnderTransit_TheSecretsUnchanged(t *testing.T) {
	svc, store, audit, localID := switched(t, 3)
	ctx := context.Background()
	r, err := svc.RewrapDue(ctx, "")
	if err != nil || r.Resealed != 3 || r.Next != "" || r.Skipped != 0 {
		t.Fatalf("RewrapDue = %+v, %v; want 3 re-sealed, the last page", r, err)
	}
	for i := 0; i < 3; i++ {
		id := fmt.Sprintf("acc%02d", i)
		if k := keyOf(t, store, id); k != "transit:transit/vault" {
			t.Fatalf("%s is sealed under %q after the rewrap", id, k)
		}
		v, _ := store.CurrentVersion(ctx, id)
		if string(v.EncryptedMaterial[:4]) != "OBT1" {
			t.Fatalf("%s is not a Transit envelope", id)
		}
	}
	tok, _, err := svc.AuthorizeScope(ctx, "s-rewrap", "acc01", "ssh-proxy", 60e9)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := fetchMaterial(svc, ctx, tok, "ssh-proxy"); err != nil || string(got) != "secret-acc01" {
		t.Fatalf("the secret after the rewrap: %q, %v", got, err)
	}
	audit.mu.Lock()
	events := strings.Join(audit.events, "\n")
	audit.mu.Unlock()
	if strings.Count(events, "|vault.secret_rewrapped|") != 3 || strings.Contains(events, "user") {
		t.Fatalf("audit:\n%s", events)
	}
	if r, err := svc.RewrapDue(ctx, ""); r.Found != 0 || err != nil {
		t.Fatalf("a second pass: %+v, %v; want nothing found", r, err)
	}
	if left, _ := store.SealedUnder(ctx, []string{localID}, "", 100); len(left) != 0 {
		t.Fatalf("%d versions still under the local key", len(left))
	}
}

func TestRewrapDue_WithoutTheAudit_NothingIsResealed(t *testing.T) {
	svc, store, audit, localID := switched(t, 2)
	audit.down = true
	if _, err := svc.RewrapDue(context.Background(), ""); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("err = %v, want ErrAuditUnavailable", err)
	}
	for _, id := range []string{"acc00", "acc01"} {
		if k := keyOf(t, store, id); k != localID {
			t.Fatalf("%s was re-sealed without the audit (%q)", id, k)
		}
	}
}

func TestRewrapDue_APageAtATime(t *testing.T) {
	svc, _, _, _ := switched(t, application.RewrapBatch+3)
	ctx := context.Background()
	r, err := svc.RewrapDue(ctx, "")
	if err != nil || r.Resealed != application.RewrapBatch || r.Next == "" {
		t.Fatalf("first page: %+v, %v; want a full page and a cursor", r, err)
	}
	if r, err := svc.RewrapDue(ctx, r.Next); err != nil || r.Resealed != 3 || r.Next != "" {
		t.Fatalf("second page: %+v, %v; want the 3 left, and the end", r, err)
	}
}

// A version the earlier key does not open — another era's key, or altered — is skipped and
// counted; the others behind it are re-sealed all the same, and the version stays as it was.
func TestRewrapDue_AVersionThatDoesNotOpenIsSkipped_TheOthersAreNot(t *testing.T) {
	svc, store, _, localID := switched(t, 3)
	ctx := context.Background()
	broken, _ := store.CurrentVersion(ctx, "acc00")
	broken.EncryptedMaterial[len(broken.EncryptedMaterial)-1] ^= 1
	r, err := svc.RewrapDue(ctx, "")
	if err != nil || r.Resealed != 2 || r.Skipped != 1 || r.Found != 3 {
		t.Fatalf("RewrapDue = %+v, %v; want 2 re-sealed and 1 skipped", r, err)
	}
	if k := keyOf(t, store, "acc00"); k != localID {
		t.Fatalf("the version that does not open was changed: %q", k)
	}
	for _, id := range []string{"acc01", "acc02"} {
		if k := keyOf(t, store, id); k != "transit:transit/vault" {
			t.Fatalf("%s behind the broken one was not re-sealed: %q", id, k)
		}
	}
}

func TestRewrapDue_AVaultWithoutAnEarlierKeyHasNothingToDo(t *testing.T) {
	local, _ := infrastructure.NewLocalKMSFromHexKey(strings.Repeat("ab", 32))
	store := infrastructure.NewInMemoryStore()
	audit := &fakeAudit{}
	svc := application.NewVaultService(store, store, store, local, &fakeAuthz{allowed: true}).WithRotation(newFakeTarget(), audit)
	if err := onboardTest(svc, context.Background(), adminRoles, "acc", "acc", "root", host, "ssh", domain.RotationManual, []byte("s")); err != nil {
		t.Fatal(err)
	}
	if r, err := svc.RewrapDue(context.Background(), ""); r != (application.Rewrapped{}) || err != nil {
		t.Fatalf("%+v, %v", r, err)
	}
}

func TestResealIf_AVersionChangedMeanwhileIsLeftAsItIs(t *testing.T) {
	_, store, _, localID := switched(t, 1)
	v, _ := store.CurrentVersion(context.Background(), "acc00")
	if ok, err := store.ResealIf(context.Background(), v.ID, "transit:transit/vault", []byte("x"), "other"); ok || err != nil {
		t.Fatalf("a compare-and-swap on the wrong old key: %v, %v", ok, err)
	}
	if k := keyOf(t, store, "acc00"); k != localID {
		t.Fatalf("the version changed: %q", k)
	}
}

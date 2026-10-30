package proxycore

import (
	"context"
	"errors"
	"testing"
)

type fakeVault struct {
	material []byte
	calls    int
	err      error
}

func (f *fakeVault) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (Fetched, error) {
	f.calls++
	if f.err != nil {
		return Fetched{}, f.err
	}
	// Return a copy, as a real Vault would over the wire — the test holds
	// its own reference so it can assert on original vs. purged bytes
	// independently.
	cp := make([]byte, len(f.material))
	copy(cp, f.material)
	return Fetched{Type: "password", Material: cp, TargetHost: "10.0.0.5:22", HostKey: "ssh-ed25519 AAAA"}, nil
}

func TestCredentialFetcher_PurgeZeroesMemory(t *testing.T) {
	vault := &fakeVault{material: []byte("s3cr3t-password")}
	fetcher := NewCredentialFetcher(vault, "ssh-proxy-instance-1")

	cred, err := fetcher.Fetch(context.Background(), "scope-token-abc")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if got := string(cred.Material()); got != "s3cr3t-password" {
		t.Fatalf("unexpected material before purge: %q", got)
	}

	cred.Purge()

	for i, b := range cred.material {
		if b != 0 {
			t.Fatalf("byte %d not zeroed after purge: %v", i, cred.material)
		}
	}
}

func TestCredential_MaterialPanicsAfterPurge(t *testing.T) {
	cred := newCredential("password", []byte("secret"))
	cred.Purge()

	defer func() {
		if r := recover(); r == nil {
			t.Fatal("expected panic when accessing Material() after Purge()")
		}
	}()
	cred.Material()
}

func TestCredentialFetcher_VaultErrorNeverProducesCredential(t *testing.T) {
	vault := &fakeVault{err: errors.New("scope token rejected")}
	fetcher := NewCredentialFetcher(vault, "ssh-proxy-instance-1")

	cred, err := fetcher.Fetch(context.Background(), "replayed-token")
	if err == nil {
		t.Fatal("expected error for rejected scope token")
	}
	if cred != nil {
		t.Fatal("no Credential should be constructed on Vault error")
	}
}

func TestCredential_PurgeIsIdempotent(t *testing.T) {
	cred := newCredential("password", []byte("secret"))
	cred.Purge()
	cred.Purge() // must not panic on double purge
}

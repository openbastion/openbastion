package infrastructure

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/screenstream"
)

type nopTyper struct{}

func (nopTyper) TypeSecret(context.Context, []byte) error { return nil }

type nopRecorder struct{}

func (nopRecorder) RecordSecretInput(context.Context, proxycore.SecretInputEvidence) error {
	return nil
}

// ADR-0133 §2: a paste token is for one live session, used once, until it expires.
func TestSecretInputRegistry_PasteTokens(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	registry := NewSecretInputRegistry()
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	registry.now = func() time.Time { return now }
	var token, other [screenstream.PasteTokenSize]byte
	token[0], other[0] = 1, 2
	if err := registry.AuthorizePaste("sess-1", "acc-1", token, time.Minute); !errors.Is(err, ErrSecretSessionInactive) {
		t.Fatalf("a session not live: %v", err)
	}
	unregister := registry.Register(ctx, "sess-1", "rdp", "desk:3389", "operator", nopTyper{}, nopRecorder{})
	defer unregister()
	for name, try := range map[string]func() error{
		"an empty token": func() error {
			return registry.AuthorizePaste("sess-1", "acc-1", [screenstream.PasteTokenSize]byte{}, time.Minute)
		},
		"61 seconds":                func() error { return registry.AuthorizePaste("sess-1", "acc-1", token, 61*time.Second) },
		"no account":                func() error { return registry.AuthorizePaste("sess-1", "", token, time.Minute) },
		"a session ID of a newline": func() error { return registry.AuthorizePaste("sess\n1", "acc-1", token, time.Minute) },
	} {
		if err := try(); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
	if err := registry.AuthorizePaste("sess-1", "acc-1", token, time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := registry.AuthorizePaste("sess-1", "acc-1", token, time.Minute); !errors.Is(err, ErrPasteGrantInvalid) {
		t.Fatalf("the same token twice: %v", err)
	}
	if _, ok := registry.TakePaste("sess-2", token); ok {
		t.Fatal("a token of another session taken")
	}
	if _, ok := registry.TakePaste("sess-1", token); ok {
		t.Fatal("a token taken by another session is still usable") // taken whatever comes next
	}
	if err := registry.AuthorizePaste("sess-1", "acc-1", other, time.Minute); err != nil {
		t.Fatal(err)
	}
	if account, ok := registry.TakePaste("sess-1", other); !ok || account != "acc-1" {
		t.Fatalf("take: %q %v", account, ok)
	}
	if _, ok := registry.TakePaste("sess-1", other); ok {
		t.Fatal("a token used twice")
	}
	var late [screenstream.PasteTokenSize]byte
	late[0] = 3
	if err := registry.AuthorizePaste("sess-1", "acc-1", late, time.Minute); err != nil {
		t.Fatal(err)
	}
	now = now.Add(time.Minute)
	if _, ok := registry.TakePaste("sess-1", late); ok {
		t.Fatal("an expired token taken")
	}
	if registry.PasteAuditor() != nil {
		t.Fatal("an auditor out of nothing")
	}
	var nilRegistry *SecretInputRegistry
	if _, ok := nilRegistry.TakePaste("sess-1", token); ok {
		t.Fatal("a nil registry takes")
	}
}

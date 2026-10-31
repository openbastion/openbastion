package infrastructure_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

// ADR-0043: the memory store refuses what the database refuses — the same id, or the same
// name on the same target — instead of overwriting the account.
func TestInMemoryStore_Create_ADuplicateIsErrAlreadyExists(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	ctx := context.Background()
	acc := func(id, name, host string) *domain.PrivilegedAccount {
		return &domain.PrivilegedAccount{ID: id, Name: name, Username: "u", TargetHost: host, Protocol: "ssh", RotationPolicy: domain.RotationManual}
	}
	if err := store.Create(ctx, acc("a", "db", "h:22")); err != nil {
		t.Fatal(err)
	}
	if err := store.Create(ctx, acc("a", "other", "other:22")); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("the same id: %v", err)
	}
	if err := store.Create(ctx, acc("b", "db", "h:22")); !errors.Is(err, domain.ErrAlreadyExists) {
		t.Fatalf("the same name on the same target: %v", err)
	}
	if a, _ := store.Get(ctx, "a"); a.Name != "db" {
		t.Fatalf("the first account was overwritten: %+v", a)
	}
	// Counter-proof: the same name on another target is another account.
	if err := store.Create(ctx, acc("c", "db", "other:22")); err != nil {
		t.Fatalf("the same name elsewhere: %v", err)
	}
}

package application_test

import (
	"context"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func TestVerifyChain_PassesOnUntamperedHistory(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)

	for i := 0; i < 5; i++ {
		if _, err := svc.EmitEvent(ctx, "user1", "session.connect", "session", "s1", true); err != nil {
			t.Fatalf("EmitEvent: %v", err)
		}
	}

	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("expected untampered chain to verify, got: %v", err)
	}
}

func TestVerifyChain_DetectsRetroactiveTampering(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)

	for i := 0; i < 3; i++ {
		if _, err := svc.EmitEvent(ctx, "user1", "session.connect", "session", "s1", true); err != nil {
			t.Fatalf("EmitEvent: %v", err)
		}
	}

	// Simulate an attacker rewriting history directly in storage — exactly
	// the scenario doc 06 §4 and Guide Sécurité §9 claim is detectable.
	events, err := store.All(ctx)
	if err != nil {
		t.Fatalf("All: %v", err)
	}
	events[1].ResourceID = "s1-tampered"

	if err := svc.VerifyChain(ctx); err == nil {
		t.Fatal("expected VerifyChain to detect retroactive tampering, but it passed")
	}
}

func TestEmitEvent_ChainsSequentialEvents(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)

	first, err := svc.EmitEvent(ctx, "", "vault.rotate", "privileged_account", "acc1", true)
	if err != nil {
		t.Fatalf("EmitEvent (first): %v", err)
	}
	second, err := svc.EmitEvent(ctx, "", "session.connect", "session", "s1", true)
	if err != nil {
		t.Fatalf("EmitEvent (second): %v", err)
	}

	if len(first.PrevHash) != 0 {
		t.Fatalf("genesis event should have empty prev_hash, got %x", first.PrevHash)
	}
	if string(second.PrevHash) != string(first.Hash) {
		t.Fatal("second event's prev_hash must equal the first event's hash")
	}
}

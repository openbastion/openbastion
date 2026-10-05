package application

import (
	"context"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// TestVerifyChain_DetectsBrokenLinkEvenWhenSelfHashIsRecomputed covers a
// more sophisticated attack than a naive field edit: the attacker edits
// event N's fields AND recomputes event N's own hash so it stays
// internally consistent — but does not (cannot, without also rewriting
// every later event) update event N+1's prev_hash to match. VerifyChain's
// link check, not just its self-hash check, is what catches this
// (OpenBastion_06_Modele_Donnees.md §4).
func TestVerifyChain_DetectsBrokenLinkEvenWhenSelfHashIsRecomputed(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store)

	for i := 0; i < 3; i++ {
		if _, err := svc.EmitEvent(ctx, "user1", "session.connect", "session", "s1", true); err != nil {
			t.Fatalf("EmitEvent: %v", err)
		}
	}

	events, err := store.All(ctx)
	if err != nil {
		t.Fatalf("All: %v", err)
	}

	tampered := events[1]
	tampered.ResourceID = "s1-tampered"
	tampered.Hash = computeHash(tampered) // attacker keeps the self-hash consistent

	if err := svc.VerifyChain(ctx); err == nil {
		t.Fatal("expected VerifyChain to detect the broken link to the next event, even with a self-consistent hash")
	}
}

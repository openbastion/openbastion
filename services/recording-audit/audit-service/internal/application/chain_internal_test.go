package application

import (
	"context"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// TestVerifyChain_DetectsBrokenLinkEvenWhenSelfHashIsRecomputed covers a
// more sophisticated attack than a naive field edit: the attacker edits
// event N's fields AND recomputes event N's own hash so it stays
// internally consistent — but does not (cannot, without also rewriting
// every later event) update event N+1's prev_hash to match. VerifyChain's
// link check, not just its self-hash check, is what catches this
// (docs/architecture/data-architecture.md §4).
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

// TestEmitEvent_TimestampIsTruncatedToMicrosecondPrecision pins a real
// bug found by actually running VerifyChain against a PostgreSQL-backed
// chain across a process restart (TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart,
// test/integration — see NOTES_SANDBOX.md), invisible with InMemoryStore
// alone. PostgreSQL's TIMESTAMPTZ column (001_init.sql) only has
// microsecond precision; computeHash hashes Timestamp byte-for-byte via
// UnixNano, so a hash computed on time.Now().UTC()'s full nanosecond
// precision could never be recomputed correctly once that value silently
// lost its last three digits on the way through a real database —
// VerifyChain would report every single event as tampered. The fix
// truncates before the hash is ever computed, so this is independent of
// which store is wired in: no storage engine's own precision can ever
// again disagree with what was hashed.
func TestEmitEvent_TimestampIsTruncatedToMicrosecondPrecision(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store)

	e, err := svc.EmitEvent(ctx, "user1", "session.connect", "session", "s1", true)
	if err != nil {
		t.Fatalf("EmitEvent: %v", err)
	}
	if !e.Timestamp.Equal(e.Timestamp.Truncate(time.Microsecond)) {
		t.Fatalf("expected Timestamp to already be truncated to microsecond precision, got nanosecond component %d", e.Timestamp.Nanosecond())
	}
}

package application

// The chain is keyed (ADR-0027): without the key nobody can make a rewritten chain verify, a
// key is named without being revealed, and a key can be rotated without losing what the old
// one signed.

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

const (
	keyA = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	keyB = "f0e0d0c0b0a090807060504030201000f0e0d0c0b0a090807060504030201000"
)

func mustKeys(t *testing.T, current, previous string) *ChainKeys {
	t.Helper()
	k, err := ParseChainKeys(current, previous)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestParseChainKeys_TakesKeysAndNeverRepeatsOne(t *testing.T) {
	k := mustKeys(t, keyA, " "+keyB+" ")
	if k.Count() != 2 || k.CurrentID() != ChainKeyID(mustHex(keyA)) {
		t.Fatalf("keys: %d, current %s", k.Count(), k.CurrentID())
	}
	for _, c := range []struct{ current, previous string }{
		{"", ""}, {"abcd", ""}, {strings.Repeat("zz", 32), ""}, {keyA + "00", ""},
		{keyA, "nothex"}, {keyA, keyB + ",abcd"},
	} {
		_, err := ParseChainKeys(c.current, c.previous)
		if !errors.Is(err, ErrBadChainKey) {
			t.Fatalf("%q / %q: want ErrBadChainKey, got %v", c.current, c.previous, err)
		}
		for _, v := range []string{c.current, c.previous, keyA, keyB} {
			if len(v) > 8 && strings.Contains(err.Error(), v) {
				t.Fatalf("the error repeats a key: %v", err)
			}
		}
	}
}

func mustHex(s string) []byte {
	b, _ := hex.DecodeString(s)
	return b
}

func TestChainKeyID_NamesAKeyWithoutRevealingIt(t *testing.T) {
	a, b := ChainKeyID(mustHex(keyA)), ChainKeyID(mustHex(keyB))
	if a == b || len(a) != 16 || a != ChainKeyID(mustHex(keyA)) || strings.Contains(keyA, a) {
		t.Fatalf("key ids %q %q", a, b)
	}
	if RandomChainKeys().CurrentID() == RandomChainKeys().CurrentID() {
		t.Fatal("two random keys have the same id")
	}
}

// What an attacker who can write the store, but holds no key, can do: rewrite an event and
// recompute the tail in every format computable without the key.
func TestVerifyChain_ATailRecomputedWithoutTheKeyIsFound(t *testing.T) {
	for _, as := range []int{domain.HashV2, domain.HashV3} {
		ctx := context.Background()
		store := infrastructure.NewInMemoryStore()
		svc := NewAuditService(store).WithChainKeys(mustKeys(t, keyA, ""))
		for i := 0; i < 4; i++ {
			_, _ = svc.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true)
		}
		events, _ := store.All(ctx)
		prev := events[1].PrevHash
		for i := 1; i < len(events); i++ {
			e := events[i]
			if i == 1 {
				e.ResourceID = "s_forged"
			}
			e.PrevHash, e.HashVersion = prev, as
			if as == domain.HashV2 {
				e.Emitter, e.KeyID = "", ""
				e.Hash = computeHashV2(e)
			} else {
				e.Hash = computeHashV3(make([]byte, ChainKeyBytes), e) // a key that is not the chain's
			}
			prev = e.Hash
		}
		if err := svc.VerifyChain(ctx); err == nil {
			t.Fatalf("a tail recomputed as v%d without the key went unnoticed", as)
		}
	}
}

func TestVerifyChain_AKeyCanBeRotatedWithoutLosingWhatTheOldOneSigned(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	old := NewAuditService(store).WithChainKeys(mustKeys(t, keyA, ""))
	_, _ = old.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true)

	onlyNew := NewAuditService(store).WithChainKeys(mustKeys(t, keyB, ""))
	err := onlyNew.VerifyChain(ctx)
	if err == nil || !strings.Contains(err.Error(), ChainKeyID(mustHex(keyA))) || strings.Contains(err.Error(), keyA) {
		t.Fatalf("a chain signed by a key not held: %v, want a refusal naming the key's id, not the key", err)
	}

	rotated := NewAuditService(store).WithChainKeys(mustKeys(t, keyB, keyA))
	e, _ := rotated.EmitEvent(ctx, "u_1", "session.read", "session", "s2", true)
	if e.KeyID != ChainKeyID(mustHex(keyB)) {
		t.Fatalf("a new event is signed with %s, want the current key", e.KeyID)
	}
	if err := rotated.VerifyChain(ctx); err != nil {
		t.Fatalf("old key kept for verification: %v", err)
	}
}

func TestEmitEventAs_TheEmitterIsCoveredAndBounded(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store)
	e, err := svc.EmitEventAs(ctx, "command-recorder", "u_1", "recording.read", "session", "s1", true)
	if err != nil || e.Emitter != "command-recorder" {
		t.Fatalf("%+v %v", e, err)
	}
	_, _ = svc.EmitEventAs(ctx, "session-broker", "u_1", "session.read", "session", "s1", true)
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
	events, _ := store.All(ctx)
	events[0].Emitter = "session-broker" // passing an event off as another service's
	if err := svc.VerifyChain(ctx); err == nil {
		t.Fatal("a changed emitter went unnoticed")
	}
	for _, bad := range []string{"Session-Broker", "a b", "x/y", strings.Repeat("a", MaxNameBytes+1), "evil\n"} {
		if _, err := svc.EmitEventAs(ctx, bad, "u_1", "session.read", "session", "s1", true); !errors.Is(err, domain.ErrInvalidEvent) {
			t.Fatalf("emitter %q: %v", bad, err)
		}
	}
}

// The unkeyed formats cover neither emitter nor key id: a v1 or v2 row that carries one was
// not written so.
func TestVerifyChain_AnUnkeyedEventCarriesNoEmitterNorKey(t *testing.T) {
	for _, set := range []func(*domain.Event){
		func(e *domain.Event) { e.Emitter = "session-broker" },
		func(e *domain.Event) { e.KeyID = "0011223344556677" },
	} {
		ctx := context.Background()
		store := infrastructure.NewInMemoryStore()
		legacyChain(t, store, 2)
		events, _ := store.All(ctx)
		set(events[1])
		if err := NewAuditService(store).VerifyChain(ctx); err == nil {
			t.Fatalf("a v1 event carrying %+v went unnoticed", events[1])
		}
	}
}

// v3 is fixed like the others: computed independently (Python's hmac) before being written here.
func TestComputeHashV3_TheFormatIsFixed(t *testing.T) {
	e := &domain.Event{
		ID: "evt_1", Timestamp: time.Date(2026, 10, 30, 12, 0, 0, 123456000, time.UTC), ActorID: "user_ab",
		Action: "session.read", ResourceType: "session", ResourceID: "session_01", Success: true,
		PrevHash: []byte{0xde, 0xad, 0xbe, 0xef}, HashVersion: domain.HashV3, Emitter: "session-broker",
		KeyID: ChainKeyID(mustHex(keyA)),
	}
	if got := hex.EncodeToString(computeHashV3(mustHex(keyA), e)); got != wantV3 || e.KeyID != wantKeyIDA {
		t.Fatalf("v3 = %s (want %s), key id %s (want %s)", got, wantV3, e.KeyID, wantKeyIDA)
	}
}

const (
	wantKeyIDA = "b6e88eca7f335c67"
	wantV3     = "70f1d4f403ec07713499fc33bd9ad595011da29fbc0b4414a870137a094f1467"
)

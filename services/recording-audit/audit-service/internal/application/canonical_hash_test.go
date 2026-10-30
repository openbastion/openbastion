package application

// The hash covers each field AS a field (ADR-0026): moving bytes from one field to its
// neighbour is an edit, and an edit of a stored event is found.

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

// Every pair of neighbouring fields, with one byte moved across the boundary between them.
func TestVerifyChain_DetectsBytesMovedBetweenNeighbouringFields(t *testing.T) {
	for name, shift := range map[string]func(e *eventFields){
		"id → actor": func(e *eventFields) { e.actor = e.id[len(e.id)-1:] + e.actor; e.id = e.id[:len(e.id)-1] },
		"actor → action": func(e *eventFields) {
			e.action = e.actor[len(e.actor)-1:] + e.action
			e.actor = e.actor[:len(e.actor)-1]
		},
		"action → resource type": func(e *eventFields) {
			e.typ = e.action[len(e.action)-1:] + e.typ
			e.action = e.action[:len(e.action)-1]
		},
		"resource type → resource id": func(e *eventFields) { e.res = e.typ[len(e.typ)-1:] + e.res; e.typ = e.typ[:len(e.typ)-1] },
		"resource id → actor (empty)": func(e *eventFields) { e.actor = ""; e.id += "u" }, // stands for a field that empties into its neighbour
	} {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			store := infrastructure.NewInMemoryStore()
			svc := NewAuditService(store)
			for _, actor := range []string{"user_ab", "u", "user_cd"} {
				if _, err := svc.EmitEvent(ctx, actor, "session.read", "session", "session_01", true); err != nil {
					t.Fatal(err)
				}
			}
			events, _ := store.All(ctx)
			e := events[1]
			f := eventFields{e.ID, e.ActorID, e.Action, e.ResourceType, e.ResourceID}
			shift(&f)
			e.ID, e.ActorID, e.Action, e.ResourceType, e.ResourceID = f.id, f.actor, f.action, f.typ, f.res

			if err := svc.VerifyChain(ctx); err == nil {
				t.Fatalf("bytes moved between two fields of a stored event (%+v) went unnoticed", f)
			}
		})
	}
}

type eventFields struct{ id, actor, action, typ, res string }

// legacyChain builds a chain as the Audit Service wrote it before ADR-0026: v1 hashes.
func legacyChain(t *testing.T, store *infrastructure.InMemoryStore, n int) {
	t.Helper()
	var prev []byte
	for i := 0; i < n; i++ {
		e := &domain.Event{
			ID: nextID(), Timestamp: time.Date(2026, 1, 2, 3, 4, 5, i*1000, time.UTC), ActorID: "user_old",
			Action: "session.connect", ResourceType: "session", ResourceID: "s_old", Success: true,
			PrevHash: prev, HashVersion: domain.HashV1,
		}
		e.Hash = computeHashV1(e)
		if err := store.Append(context.Background(), e); err != nil {
			t.Fatal(err)
		}
		prev = e.Hash
	}
}

func TestEmitEvent_WritesTheCurrentFormat(t *testing.T) {
	svc := NewAuditService(infrastructure.NewInMemoryStore())
	e, err := svc.EmitEvent(context.Background(), "u_1", "session.read", "session", "s1", true)
	if err != nil {
		t.Fatal(err)
	}
	// The current format is v3 since ADR-0027: keyed, and neither unkeyed format.
	key := svc.keys.keys[svc.keys.current]
	if e.HashVersion != domain.HashV3 || e.KeyID != svc.keys.current || string(e.Hash) != string(computeHashV3(key, e)) ||
		string(e.Hash) == string(computeHashV2(e)) || string(e.Hash) == string(computeHashV1(e)) {
		t.Fatalf("a new event is not signed in v3 with the current key: version %d, key %q", e.HashVersion, e.KeyID)
	}
}

// A chain written before ADR-0026 still verifies, and grows in v2.
func TestVerifyChain_ALegacyChainVerifies_AndGrowsInTheNewFormat(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	legacyChain(t, store, 3)
	svc := NewAuditService(store)
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("the legacy chain: %v", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := svc.EmitEvent(ctx, "u_new", "session.read", "session", "s_new", true); err != nil {
			t.Fatal(err)
		}
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("v1 then v2: %v", err)
	}
	events, _ := store.All(ctx)
	if events[2].HashVersion != domain.HashV1 || events[3].HashVersion != domain.HashV3 || string(events[3].PrevHash) != string(events[2].Hash) {
		t.Fatal("the first event in the current format does not continue the v1 chain")
	}
}

// Versions move forward only: an event cannot be passed off in the weaker format, even with
// every hash and link recomputed to match.
func TestVerifyChain_RefusesAVersionThatGoesBack_OrIsUnknown(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		versions []int
		ok       bool
	}{
		"v1 v1 v2 v2":      {[]int{1, 1, 2, 2}, true},
		"v2 v1":            {[]int{2, 1}, false},
		"v1 v2 v1 v2":      {[]int{1, 2, 1, 2}, false},
		"an unknown 4":     {[]int{2, 4}, false},
		"a v3 with no key": {[]int{2, 3}, false},
		"a version of 0":   {[]int{0}, false},
		"a negative value": {[]int{2, -1}, false},
	} {
		t.Run(name, func(t *testing.T) {
			store := infrastructure.NewInMemoryStore()
			var prev []byte
			for i, v := range c.versions {
				e := &domain.Event{ID: nextID(), Timestamp: time.Date(2026, 1, 2, 3, 4, 5, i*1000, time.UTC), ActorID: "u",
					Action: "session.read", ResourceType: "session", ResourceID: "s", PrevHash: prev, HashVersion: v}
				e.Hash = computeHash(e)
				if e.Hash == nil {
					e.Hash = computeHashV2(e) // an attacker writes some hash for a version that has none
				}
				_ = store.Append(ctx, e)
				prev = e.Hash
			}
			err := NewAuditService(store).VerifyChain(ctx)
			if (err == nil) != c.ok {
				t.Fatalf("versions %v: err = %v, want ok=%v", c.versions, err, c.ok)
			}
		})
	}
}

// Changing an event's version, and nothing else, is an edit.
func TestVerifyChain_DetectsAChangedVersion(t *testing.T) {
	ctx := context.Background()
	for _, to := range []int{domain.HashV1, domain.HashV2, 4} {
		store := infrastructure.NewInMemoryStore()
		svc := NewAuditService(store)
		for i := 0; i < 3; i++ {
			_, _ = svc.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true)
		}
		events, _ := store.All(ctx)
		events[2].HashVersion = to // the last one: no later version to contradict it
		if err := svc.VerifyChain(ctx); err == nil {
			t.Fatalf("a v3 event relabelled %d went unnoticed", to)
		}
	}
	store := infrastructure.NewInMemoryStore()
	legacyChain(t, store, 2)
	events, _ := store.All(ctx)
	events[1].HashVersion = domain.HashV2
	if err := NewAuditService(store).VerifyChain(ctx); err == nil {
		t.Fatal("a v1 event relabelled v2 went unnoticed")
	}
}

// The two formats are fixed: a stored chain is verified with them forever. These vectors
// change only with a new version.
func TestComputeHash_TheFormatsAreFixed(t *testing.T) {
	e := &domain.Event{
		ID: "evt_1", Timestamp: time.Date(2026, 10, 30, 12, 0, 0, 123456000, time.UTC), ActorID: "user_ab",
		Action: "session.read", ResourceType: "session", ResourceID: "session_01", Success: true,
		PrevHash: []byte{0xde, 0xad, 0xbe, 0xef},
	}
	e.HashVersion = domain.HashV1
	v1 := hex.EncodeToString(computeHash(e))
	e.HashVersion = domain.HashV2
	v2 := hex.EncodeToString(computeHash(e))
	if v1 != wantV1 || v2 != wantV2 {
		t.Fatalf("v1 = %s (want %s)\nv2 = %s (want %s)", v1, wantV1, v2, wantV2)
	}
}

// Computed independently of this code (Python's hashlib, from the description of each format)
// before being written here; v1 is also what the code before ADR-0026 computed.
const (
	wantV1 = "f72a346b977a0ea5a4484370f962add6c8230702b4cb457b57eccb97b850724f"
	wantV2 = "1c4cd3f0e745236cb372e8a2f1f55672bbd72554d9221fb93ef434e32adb99a0"
)

// An unknown version has no unkeyed hash at all, and v3 has none without its key: neither
// unkeyed format may stand in for them.
func TestComputeHash_AnUnknownVersionHasNoHash(t *testing.T) {
	for _, v := range []int{0, -1, 3, 4, 99} {
		e := &domain.Event{ID: "evt", Action: "session.read", ResourceType: "session", ResourceID: "s", HashVersion: v}
		if h := computeHash(e); h != nil {
			t.Fatalf("version %d hashed to %x", v, h)
		}
	}
}

// A stored hash may be empty (BYTEA NOT NULL takes ”): with an unknown version, whose hash is
// nil, the empty hash "matches". What refuses that row is the version rule, not the hash.
func TestVerifyChain_AnEmptyHashUnderAnUnknownVersionIsRefused(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := NewAuditService(store)
	_, _ = svc.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true)
	_, _ = svc.EmitEvent(ctx, "u_1", "session.read", "session", "s1", true)
	events, _ := store.All(ctx)
	last := events[1]
	last.HashVersion, last.Hash, last.ActorID = 7, []byte{}, "someone_else"
	if err := svc.VerifyChain(ctx); err == nil {
		t.Fatal("the last event rewritten with an empty hash under version 7 went unnoticed")
	}
}

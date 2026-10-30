package application

// The head of the chain is anchored outside the database (ADR-0028).

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

type memoryAnchors struct {
	list        []domain.Anchor
	checkpoints []domain.Checkpoint
	err         error
}

func (m *memoryAnchors) AppendCheckpoint(_ context.Context, c domain.Checkpoint) error {
	if m.err != nil {
		return m.err
	}
	m.checkpoints = append(m.checkpoints, c)
	return nil
}

func (m *memoryAnchors) Checkpoints(context.Context) ([]domain.Checkpoint, error) {
	if m.err != nil {
		return nil, m.err
	}
	return append([]domain.Checkpoint(nil), m.checkpoints...), nil
}

func (m *memoryAnchors) Append(_ context.Context, a domain.Anchor) error {
	if m.err != nil {
		return m.err
	}
	m.list = append(m.list, a)
	return nil
}

func (m *memoryAnchors) All(context.Context) ([]domain.Anchor, error) {
	if m.err != nil {
		return nil, m.err
	}
	return append([]domain.Anchor(nil), m.list...), nil
}

// cuttableStore is a store whose end an attacker can cut: keep > 0 hides every event after
// the first keep.
type cuttableStore struct {
	*infrastructure.InMemoryStore
	keep int
}

func (c *cuttableStore) All(ctx context.Context) ([]*domain.Event, error) {
	all, err := c.InMemoryStore.All(ctx)
	if c.keep > 0 && len(all) > c.keep {
		all = all[:c.keep]
	}
	return all, err
}

func (c *cuttableStore) Last(ctx context.Context) (*domain.Event, error) {
	all, err := c.All(ctx)
	if err != nil || len(all) == 0 {
		return nil, err
	}
	return all[len(all)-1], nil
}

func anchoredService(t *testing.T) (*AuditService, *cuttableStore, *memoryAnchors) {
	t.Helper()
	store := &cuttableStore{InMemoryStore: infrastructure.NewInMemoryStore()}
	sink := &memoryAnchors{}
	return NewAuditService(store).WithChainKeys(mustKeys(t, keyA, "")).WithAnchors(sink), store, sink
}

func emitN(t *testing.T, svc *AuditService, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := svc.EmitEvent(context.Background(), "u_1", "session.read", "session", "s1", true); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAnchor_NamesTheHeadOnce_AndNothingForAnEmptyChain(t *testing.T) {
	ctx := context.Background()
	svc, store, sink := anchoredService(t)
	if wrote, err := svc.Anchor(ctx); wrote || err != nil {
		t.Fatalf("an empty chain was anchored: %v %v", wrote, err)
	}
	emitN(t, svc, 3)
	if wrote, err := svc.Anchor(ctx); !wrote || err != nil {
		t.Fatalf("the head was not anchored: %v", err)
	}
	if wrote, _ := svc.Anchor(ctx); wrote {
		t.Fatal("the same head was anchored twice")
	}
	head, _ := store.Last(ctx)
	if len(sink.list) != 1 || sink.list[0].EventID != head.ID || string(sink.list[0].Hash) != string(head.Hash) || sink.list[0].KeyID != svc.keys.current {
		t.Fatalf("anchors %+v, want one naming %s", sink.list, head.ID)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
}

// What the database says after the fact is not what is anchored: the anchor names the event
// this process wrote, with the hash it computed — a database rewritten or cut between two
// anchors does not get its version vouched for by the next one.
func TestAnchor_NamesWhatThisProcessWrote_NotWhatTheDatabaseSaysLater(t *testing.T) {
	ctx := context.Background()
	svc, store, sink := anchoredService(t)
	emitN(t, svc, 3)
	events, _ := store.All(ctx)
	written := events[2]
	wantHash := append([]byte(nil), written.Hash...)
	written.ResourceID, written.Hash = "s_forged", []byte("forged") // rewritten in the store before the tick
	if _, err := svc.Anchor(ctx); err != nil {
		t.Fatal(err)
	}
	if len(sink.list) != 1 || string(sink.list[0].Hash) != string(wantHash) {
		t.Fatalf("the anchor took the store's word: %x, want the hash this process computed %x", sink.list[0].Hash, wantHash)
	}
	if err := svc.VerifyChain(ctx); err == nil {
		t.Fatal("the rewritten head went unnoticed")
	}
}

func TestVerifyChain_AgainstTheAnchors(t *testing.T) {
	ctx := context.Background()
	for name, c := range map[string]struct {
		attack func(store *cuttableStore, sink *memoryAnchors)
		want   string
	}{
		"the whole chain rewritten in v2": {func(store *cuttableStore, _ *memoryAnchors) {
			events, _ := store.All(ctx)
			var prev []byte
			for _, e := range events {
				e.ResourceID, e.PrevHash, e.HashVersion, e.Emitter, e.KeyID = "s_forged", prev, domain.HashV2, "", ""
				e.Hash = computeHashV2(e)
				prev = e.Hash
			}
		}, "anchor"},
		"the anchored event cut": {func(store *cuttableStore, _ *memoryAnchors) {
			store.keep = 1
		}, "not in the chain"},
		"an anchor edited": {func(_ *cuttableStore, sink *memoryAnchors) {
			sink.list[0].EventID = "evt_other"
		}, "MAC"},
		"an anchor signed by a key not held": {func(_ *cuttableStore, sink *memoryAnchors) {
			sink.list[0].KeyID = "0011223344556677"
		}, "does not hold"},
		"anchors out of order": {func(_ *cuttableStore, sink *memoryAnchors) {
			sink.list[0], sink.list[1] = sink.list[1], sink.list[0]
		}, "reordered"},
	} {
		t.Run(name, func(t *testing.T) {
			svc, store, sink := anchoredService(t)
			emitN(t, svc, 2)
			_, _ = svc.Anchor(ctx)
			emitN(t, svc, 2)
			_, _ = svc.Anchor(ctx)
			if err := svc.VerifyChain(ctx); err != nil {
				t.Fatal(err)
			}
			c.attack(store, sink)
			err := svc.VerifyChain(ctx)
			if err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("%s: %v, want an error saying %q", name, err, c.want)
			}
		})
	}
}

func TestVerifyChain_AnchorsThatCannotBeReadAreNotAVerdict(t *testing.T) {
	ctx := context.Background()
	svc, _, sink := anchoredService(t)
	emitN(t, svc, 1)
	sink.err = errors.New("read-only file system")
	if _, err := svc.Anchor(ctx); err == nil {
		t.Fatal("a failed anchor write was not reported")
	}
	if err := svc.VerifyChain(ctx); !errors.Is(err, domain.ErrAnchorsUnavailable) {
		t.Fatalf("want ErrAnchorsUnavailable, got %v", err)
	}
	// Once the sink works again, the head that could not be anchored is.
	sink.err = nil
	if wrote, err := svc.Anchor(ctx); !wrote || err != nil {
		t.Fatalf("the head was not anchored once the sink was back: %v %v", wrote, err)
	}
}

// An anchor is fixed like an event: computed independently (Python's hmac).
func TestAnchorMAC_TheFormatIsFixed(t *testing.T) {
	a := domain.Anchor{EventID: "evt_1", Hash: []byte{0xde, 0xad, 0xbe, 0xef}, At: time.Date(2026, 10, 30, 12, 0, 0, 123456000, time.UTC), KeyID: wantKeyIDA}
	if got := hexOf(anchorMAC(mustHex(keyA), a)); got != wantAnchorMAC {
		t.Fatalf("anchor MAC = %s, want %s", got, wantAnchorMAC)
	}
}

// Computed independently (Python's hmac) before being written here.
const wantAnchorMAC = "cf5e645f805589c30744e8749f3c8d77ab77de02f9b13e023627ccda942f4f85"

func hexOf(b []byte) string { return hex.EncodeToString(b) }

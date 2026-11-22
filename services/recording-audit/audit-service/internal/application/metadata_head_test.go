package application_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
)

func digestOf(s string) []byte { d := sha256.Sum256([]byte(s)); return d[:] }

// ADR-0116 §3-§5: revisions follow one another; the same one again changes nothing; another digest
// for the same revision, an older revision, or a jump of more than one is refused with the head.
func TestMetadataHead_RevisionsFollowTheHead(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	attest := func(rev uint64, digest []byte) (domain.MetadataHead, error) {
		return svc.AttestSessionMetadata(ctx, "session-broker", "session_1", rev, digest, "k1")
	}
	if _, err := attest(1, digestOf("r1")); err != nil {
		t.Fatal(err)
	}
	if _, err := attest(2, digestOf("r2")); err != nil {
		t.Fatal(err)
	}
	events, _ := store.All(ctx)
	again, err := attest(2, digestOf("r2"))
	if err != nil || again.Revision != 2 {
		t.Fatalf("the same attestation again: %+v %v", again, err)
	}
	if after, _ := store.All(ctx); len(after) != len(events) {
		t.Fatal("an idempotent attestation wrote another event")
	}
	for name, c := range map[string]struct {
		rev    uint64
		digest []byte
		key    string
		want   error
	}{
		"the head's revision, another digest": {2, digestOf("forged"), "k1", domain.ErrMetadataFork},
		"the head's revision, another key":    {2, digestOf("r2"), "k2", domain.ErrMetadataFork},
		"an older revision":                   {1, digestOf("r1"), "k1", domain.ErrMetadataRollback},
		"two ahead":                           {4, digestOf("r4"), "k1", domain.ErrMetadataGap},
	} {
		head, err := svc.AttestSessionMetadata(ctx, "session-broker", "session_1", c.rev, c.digest, c.key)
		if !errors.Is(err, c.want) || head.Revision != 2 {
			t.Errorf("%s: %v (head %d), want %v with the head", name, err, head.Revision, c.want)
		}
	}
	head, err := svc.SessionMetadataHead(ctx, "session_1")
	if err != nil || head.Revision != 2 || !bytes.Equal(head.Digest, digestOf("r2")) {
		t.Fatalf("the head: %+v %v", head, err)
	}
	if err := svc.VerifyChain(ctx); err != nil {
		t.Fatalf("the chain with its attestations: %v", err)
	}
	if none, err := svc.SessionMetadataHead(ctx, "session_other"); none != nil || err != nil {
		t.Fatalf("a session without a head: %v %v", none, err)
	}
}

// Only the Session Broker attests; nothing malformed is written.
func TestMetadataHead_OnlyTheBrokerAttests(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	for name, c := range map[string]struct {
		emitter, session, key string
		rev                   uint64
		digest                []byte
	}{
		"another service":    {"rdp-vnc-proxy", "s", "k1", 1, digestOf("x")},
		"no session":         {"session-broker", "", "k1", 1, digestOf("x")},
		"revision zero":      {"session-broker", "s", "k1", 0, digestOf("x")},
		"a short digest":     {"session-broker", "s", "k1", 1, digestOf("x")[:16]},
		"a bad key id":       {"session-broker", "s", "k 1", 1, digestOf("x")},
		"a control in an id": {"session-broker", "s\n", "k1", 1, digestOf("x")},
	} {
		if _, err := svc.AttestSessionMetadata(ctx, c.emitter, c.session, c.rev, c.digest, c.key); !errors.Is(err, domain.ErrInvalidEvent) {
			t.Errorf("%s: %v", name, err)
		}
	}
	if events, _ := store.All(ctx); len(events) != 0 {
		t.Fatalf("%d event(s) written by refused attestations", len(events))
	}
}

// A head changed in the projection no longer recomputes to the event the chain signed.
func TestMetadataHead_AnAlteredHeadIsRefused(t *testing.T) {
	ctx := context.Background()
	store := &alteringHeads{InMemoryStore: infrastructure.NewInMemoryStore()}
	svc := application.NewAuditService(store)
	if _, err := svc.AttestSessionMetadata(ctx, "session-broker", "s", 3, digestOf("r3"), "k1"); err != nil {
		t.Fatal(err)
	}
	for name, alter := range map[string]func(*domain.MetadataHead){
		"revision": func(h *domain.MetadataHead) { h.Revision = 9 },
		"digest":   func(h *domain.MetadataHead) { h.Digest = digestOf("forged") },
		"key":      func(h *domain.MetadataHead) { h.KeyID = "k2" },
		"event":    func(h *domain.MetadataHead) { h.EventID = "other" },
		"emitter":  func(h *domain.MetadataHead) { h.Emitter = "admin-cli" },
	} {
		store.alter = alter
		if _, err := svc.SessionMetadataHead(ctx, "s"); !errors.Is(err, domain.ErrMetadataHeadTampered) {
			t.Errorf("%s altered: %v", name, err)
		}
	}
	store.alter = nil
	if _, err := svc.SessionMetadataHead(ctx, "s"); err != nil {
		t.Fatalf("the head as written: %v", err)
	}
}

type alteringHeads struct {
	*infrastructure.InMemoryStore
	alter func(*domain.MetadataHead)
}

func (s *alteringHeads) MetadataHead(ctx context.Context, id string) (*domain.MetadataHead, error) {
	h, err := s.InMemoryStore.MetadataHead(ctx, id)
	if h != nil && s.alter != nil {
		s.alter(h)
	}
	return h, err
}

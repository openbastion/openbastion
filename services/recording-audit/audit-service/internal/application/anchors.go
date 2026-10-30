package application

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// AnchorSink is where anchors are kept (ADR-0028): somewhere the database does not control.
// Append adds one at the end and nothing else; All returns them in the order they were added.
//
// The same place keeps the checkpoints of the archives (ADR-0032), in the same order.
type AnchorSink interface {
	Append(ctx context.Context, a domain.Anchor) error
	All(ctx context.Context) ([]domain.Anchor, error)
	AppendCheckpoint(ctx context.Context, c domain.Checkpoint) error
	Checkpoints(ctx context.Context) ([]domain.Checkpoint, error)
}

// WithAnchors makes the service anchor its chain to sink and verify the chain against it.
func (s *AuditService) WithAnchors(sink AnchorSink) *AuditService {
	s.anchors = sink
	return s
}

// Anchor writes an anchor for the head of the chain, if the head has moved since the last one
// this process wrote; it says whether it wrote one. A chain with no event has nothing to anchor.
//
// The head is the last event this process appended, with the hash it computed — not what the
// store says now: a store rewritten or cut between two anchors must not have its version
// vouched for by the next one. Only before this process has appended anything is the store
// asked, once, for its last event (a restart): there is nothing better to trust then.
func (s *AuditService) Anchor(ctx context.Context) (bool, error) {
	if s.anchors == nil {
		return false, nil
	}
	s.anchorMu.Lock()
	defer s.anchorMu.Unlock()
	s.mu.Lock()
	head := s.tip
	s.mu.Unlock()
	if head == nil {
		last, err := s.store.Last(ctx)
		if err != nil {
			return false, err
		}
		head = last
	}
	if head == nil || head.ID == s.lastAnchored {
		return false, nil
	}
	a := domain.Anchor{EventID: head.ID, Hash: head.Hash, At: s.now().UTC().Truncate(time.Microsecond), KeyID: s.keys.current}
	a.MAC = anchorMAC(s.keys.keys[s.keys.current], a)
	if err := s.anchors.Append(ctx, a); err != nil {
		return false, err
	}
	s.lastAnchored = head.ID
	return true, nil
}

// anchorTag starts every anchor MAC: an anchor's MAC can never be taken for an event's.
const anchorTag = "openbastion.audit.anchor.v1\x00"

func anchorMAC(key []byte, a domain.Anchor) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(anchorTag))
	var n [4]byte
	for _, field := range [][]byte{[]byte(a.EventID), a.Hash, []byte(a.KeyID)} {
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		m.Write(n[:])
		m.Write(field)
	}
	var at [8]byte
	binary.BigEndian.PutUint64(at[:], uint64(a.At.UnixNano()))
	m.Write(at[:])
	return m.Sum(nil)
}

// verifyAnchors checks the chain against what was anchored outside the database: every anchor
// is genuine, names an event that is still in the chain with the same hash, and the anchors
// follow the chain's order. A chain rewritten — even entirely, in a format with no key — or
// cut before an anchored event fails here.
//
// The first `archived` anchors name events that a checkpoint says were archived (ADR-0032):
// they may be absent from the chain; when present (not yet deleted) they are checked as any.
func (s *AuditService) verifyAnchors(ctx context.Context, events []*domain.Event, anchors []domain.Anchor, archived int) error {
	position := make(map[string]int, len(events))
	for i, e := range events {
		position[e.ID] = i
	}
	last := -1
	for i, a := range anchors {
		key, held := s.keys.keys[a.KeyID]
		if !held {
			return fmt.Errorf("anchor %d: signed with chain key %q, which this service does not hold — it cannot vouch for it", i, a.KeyID)
		}
		if !hmac.Equal(anchorMAC(key, a), a.MAC) {
			return fmt.Errorf("anchor %d: its MAC does not match — the anchor was tampered with", i)
		}
		at, present := position[a.EventID]
		if !present && i < archived {
			continue
		}
		if !present {
			return fmt.Errorf("anchor %d names event %s, which is not in the chain — the chain was cut or rewritten", i, a.EventID)
		}
		if !hmac.Equal(events[at].Hash, a.Hash) {
			return fmt.Errorf("anchor %d: event %s does not have the hash it was anchored with — the chain was rewritten", i, a.EventID)
		}
		if at < last {
			return fmt.Errorf("anchor %d names event %s, before the event of an earlier anchor — the chain was reordered", i, a.EventID)
		}
		last = at
	}
	return nil
}

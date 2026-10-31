// Package application implements AuditIngestion.EmitEvent
// (proto/audit/v1/audit.proto, docs/api/grpc/README.md §7) with the hash-chaining scheme
// described in docs/architecture/data-architecture.md §4 and docs/security/audit-integrity.md:
// each event's hash covers its own fields plus the previous event's hash,
// so a retroactive edit anywhere in the chain is detectable.
package application

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// Store is the persistence port: append-only, except that what has been verified and archived
// (ADR-0032) leaves from the start of the chain.
type Store interface {
	Append(ctx context.Context, e *domain.Event) error
	Last(ctx context.Context) (*domain.Event, error) // nil, nil if the chain is empty
	All(ctx context.Context) ([]*domain.Event, error)
	// DeleteThrough removes the events from the first one through lastID, in one transaction,
	// and only if they are exactly `expected` events — otherwise nothing (ADR-0032).
	DeleteThrough(ctx context.Context, lastID string, expected int) error
}

// AuditService computes the hash chain itself — a caller never supplies or
// even knows the previous hash, by design (docs/architecture/data-architecture.md §4).
type AuditService struct {
	mu    sync.Mutex // serializes chain extension; a production deployment
	store Store      // would use a DB-level append lock instead of this

	// keys sign every event written (v3) and verify what earlier keys signed (ADR-0027).
	// Never nil: a service built by hand has a key that lives as long as it does.
	keys *ChainKeys

	// anchors keeps the heads of the chain outside the database (ADR-0028); nil = none.
	anchors      AnchorSink
	anchorMu     sync.Mutex
	lastAnchored string
	now          func() time.Time

	// tip is the last event THIS process appended, with the hash it computed (guarded by mu):
	// what an anchor names, rather than what the store says at the time of the anchor.
	tip *domain.Event

	// archive moves verified months out of the database (ADR-0032); nil = never.
	archive *archiving

	// alerts pushes the alerts written to the chain (ADR-0045); nil = none.
	alerts        AlertNotifier
	alertsUnnamed bool
}

func NewAuditService(store Store) *AuditService {
	return &AuditService{store: store, keys: RandomChainKeys(), now: time.Now}
}

// WithChainKeys sets the keys of the chain (ADR-0027).
func (s *AuditService) WithChainKeys(k *ChainKeys) *AuditService {
	s.keys = k
	return s
}

// The bounds of what an event may hold (ADR-0025). They are wider than anything an emitter
// writes today — actions such as session.breakglass_requested, the resource type "session",
// identifiers the Broker makes or the Recorder bounds to 256 bytes — and narrow enough that
// the trail is not a place to store what one likes.
const (
	MaxNameBytes = 64  // action, resource type
	MaxIDBytes   = 256 // actor, resource id
)

// validate says why an event cannot be taken, naming the field and the rule — never the value,
// which is the caller's and may be anything.
func validate(actorID, action, resourceType, resourceID string) error {
	if err := checkName("action", action, true); err != nil {
		return err
	}
	if err := checkName("resource_type", resourceType, false); err != nil {
		return err
	}
	if err := checkID("resource_id", resourceID, true); err != nil {
		return err
	}
	// An empty actor is a system action (a proxy, the Scheduler): allowed.
	return checkID("actor_id", actorID, false)
}

// checkName: 1 to 64 bytes of a-z, 0-9 and _, with dots too when dotted is set.
func checkName(field, v string, dotted bool) error {
	if v == "" || len(v) > MaxNameBytes {
		return fmt.Errorf("%w: %s must be 1 to %d bytes", domain.ErrInvalidEvent, field, MaxNameBytes)
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_' || dotted && c == '.') {
			return fmt.Errorf("%w: %s may hold only a-z, 0-9, _%s", domain.ErrInvalidEvent, field, map[bool]string{true: " and .", false: ""}[dotted])
		}
	}
	return nil
}

// checkEmitter: a service name as pkg/mtls knows them — 0 to 64 bytes of a-z, 0-9 and -.
// It comes from a verified certificate, not from the request; it is bounded all the same.
func checkEmitter(v string) error {
	if len(v) > MaxNameBytes {
		return fmt.Errorf("%w: emitter must be 0 to %d bytes", domain.ErrInvalidEvent, MaxNameBytes)
	}
	for _, c := range v {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return fmt.Errorf("%w: emitter may hold only a-z, 0-9 and -", domain.ErrInvalidEvent)
		}
	}
	return nil
}

// checkID: at most 256 bytes of UTF-8 without control characters (a newline in an identifier
// is a forged line in whatever log prints it).
func checkID(field, v string, required bool) error {
	if required && v == "" || len(v) > MaxIDBytes {
		return fmt.Errorf("%w: %s must be %s to %d bytes", domain.ErrInvalidEvent, field, map[bool]string{true: "1", false: "0"}[required], MaxIDBytes)
	}
	if !utf8.ValidString(v) {
		return fmt.Errorf("%w: %s must be UTF-8", domain.ErrInvalidEvent, field)
	}
	for _, c := range v {
		if unicode.IsControl(c) {
			return fmt.Errorf("%w: %s may not hold a control character", domain.ErrInvalidEvent, field)
		}
	}
	return nil
}

// EmitEvent appends one event to the chain with no emitter named (internal TLS disabled, or a
// caller in this process); see EmitEventAs.
func (s *AuditService) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) (*domain.Event, error) {
	return s.EmitEventAs(ctx, "", actorID, action, resourceType, resourceID, success)
}

// EmitEventAs appends one event to the chain, written by `emitter` — the service its
// certificate names (ADR-0027). An event no emitter can mean is refused
// (domain.ErrInvalidEvent) before the chain is touched (ADR-0025). The event is signed with
// the current chain key (v3).
func (s *AuditService) EmitEventAs(ctx context.Context, emitter, actorID, action, resourceType, resourceID string, success bool) (*domain.Event, error) {
	if err := validate(actorID, action, resourceType, resourceID); err != nil {
		return nil, err
	}
	if err := checkEmitter(emitter); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	last, err := s.store.Last(ctx)
	if err != nil {
		return nil, err
	}
	var prevHash []byte
	if last != nil {
		prevHash = last.Hash
	}

	e := &domain.Event{
		// Truncated to microsecond precision — not time.Now().UTC()'s
		// full nanosecond resolution — because computeHash below hashes
		// Timestamp byte-for-byte (via UnixNano), and PostgreSQL's
		// TIMESTAMPTZ column (001_init.sql) only HAS microsecond
		// precision: a value stored and reloaded loses its last three
		// nanosecond digits, silently. A hash computed on the
		// full-precision value and later recomputed from the
		// Postgres-truncated one would never match again — VerifyChain
		// would report every single event as tampered, forever, the
		// moment it round-tripped through a real database. This was a
		// real, latent bug until TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart
		// actually called verify-chain against a real Postgres-backed
		// chain — see NOTES_SANDBOX.md. Truncating here, before the hash
		// is ever computed, makes the hashed value identical to what any
		// storage engine (PostgresStore included) actually persists and
		// returns, InMemoryStore's untruncated precision notwithstanding
		// (it never had a precision mismatch to begin with, so this is a
		// no-op for it).
		ID: nextID(), Timestamp: s.now().UTC().Truncate(time.Microsecond), ActorID: actorID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		Success: success, PrevHash: prevHash, HashVersion: domain.HashV3,
		Emitter: emitter, KeyID: s.keys.current,
	}
	e.Hash = computeHashV3(s.keys.keys[s.keys.current], e)

	if err := s.store.Append(ctx, e); err != nil {
		return nil, err
	}
	tip := *e
	s.tip = &tip
	// Only what is in the chain is pushed, and only once it is (ADR-0045).
	if s.alerts != nil && s.isAlert(e) {
		s.alerts.Notify(ctx, *e)
	}
	return e, nil
}

// VerifyChain re-derives every event's hash from its own fields and
// prev_hash, and confirms each event correctly links to the next. This is
// the runnable form of "toute altération rétroactive... devient
// détectable" (docs/architecture/data-architecture.md §4, docs/security/audit-integrity.md) — not just a design claim.
func (s *AuditService) VerifyChain(ctx context.Context) error {
	events, err := s.store.All(ctx)
	if err != nil {
		return err
	}
	var anchors []domain.Anchor
	var checkpoints []domain.Checkpoint
	if s.anchors != nil {
		if anchors, err = s.anchors.All(ctx); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrAnchorsUnavailable, err)
		}
		if checkpoints, err = s.anchors.Checkpoints(ctx); err != nil {
			return fmt.Errorf("%w: %v", domain.ErrAnchorsUnavailable, err)
		}
	}
	start, err := s.startOfChain(events, checkpoints)
	if err != nil {
		return err
	}
	prevHash := start.LastHash
	version := domain.HashV1
	if start.LastVersion > version {
		version = start.LastVersion
	}
	for i, e := range events {
		// Versions only move forward (ADR-0026): once an event is v2, every later one is, so
		// that a later event cannot be passed off in the weaker format.
		if e.HashVersion < domain.HashV1 || e.HashVersion > domain.HashV3 {
			return fmt.Errorf("event %d (%s): unknown hash version %d — tampered", i, e.ID, e.HashVersion)
		}
		if e.HashVersion < version {
			return fmt.Errorf("event %d (%s): hash version %d after version %d — tampered", i, e.ID, e.HashVersion, version)
		}
		version = e.HashVersion
		var want []byte
		if e.HashVersion == domain.HashV3 {
			key, held := s.keys.keys[e.KeyID]
			if !held {
				return fmt.Errorf("event %d (%s): signed with chain key %q, which this service does not hold — it cannot vouch for it", i, e.ID, e.KeyID)
			}
			want = computeHashV3(key, e)
		} else {
			// The unkeyed formats cover neither field: one that carries them was not written so.
			if e.Emitter != "" || e.KeyID != "" {
				return fmt.Errorf("event %d (%s): an emitter or a key in a version %d event, which covers neither — tampered", i, e.ID, e.HashVersion)
			}
			want = computeHash(e)
		}
		if !hmac.Equal(want, e.Hash) || len(want) == 0 {
			return fmt.Errorf("event %d (%s): hash does not match its own fields — tampered", i, e.ID)
		}
		if string(e.PrevHash) != string(prevHash) {
			return fmt.Errorf("event %d (%s): prev_hash does not match the preceding event — chain broken", i, e.ID)
		}
		prevHash = e.Hash
	}
	if err := s.checkpointsAgree(events, checkpoints); err != nil {
		return err
	}
	return s.verifyAnchors(ctx, events, anchors, start.AnchorsCovered)
}

// computeHash computes an event's hash in the unkeyed format its HashVersion names (v1, v2).
// Any other version — v3 included, which needs a key — has no hash here: nil.
func computeHash(e *domain.Event) []byte {
	switch e.HashVersion {
	case domain.HashV1:
		return computeHashV1(e)
	case domain.HashV2:
		return computeHashV2(e)
	default:
		return nil
	}
}

// hashV2Tag starts every v2 hash: a v2 hash can never be taken for a hash of another format
// or of another kind of record.
const hashV2Tag = "openbastion.audit.event.v2\x00"

// computeHashV2 (ADR-0026) frames each variable-length field by its length, so that moving
// bytes from a field to its neighbour changes the hash: what is hashed is a sequence of
// fields, not a string that several sequences could spell.
func computeHashV2(e *domain.Event) []byte {
	h := sha256.New()
	h.Write([]byte(hashV2Tag))
	var n [4]byte
	for _, field := range [][]byte{e.PrevHash, []byte(e.ID), []byte(e.ActorID), []byte(e.Action), []byte(e.ResourceType), []byte(e.ResourceID)} {
		binary.BigEndian.PutUint32(n[:], uint32(len(field)))
		h.Write(n[:])
		h.Write(field)
	}
	var successByte [1]byte
	if e.Success {
		successByte[0] = 1
	}
	h.Write(successByte[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.Timestamp.UnixNano()))
	h.Write(tsBuf[:])
	return h.Sum(nil)
}

// computeHashV1 is the format of the events written before ADR-0026: the fields concatenated
// as they are. It is kept only to verify them — moving bytes between two neighbouring fields
// of a v1 event is not detected, and nothing is written in this format any more.
func computeHashV1(e *domain.Event) []byte {
	h := sha256.New()
	h.Write(e.PrevHash)
	h.Write([]byte(e.ID))
	h.Write([]byte(e.ActorID))
	h.Write([]byte(e.Action))
	h.Write([]byte(e.ResourceType))
	h.Write([]byte(e.ResourceID))
	var successByte [1]byte
	if e.Success {
		successByte[0] = 1
	}
	h.Write(successByte[:])
	var tsBuf [8]byte
	binary.BigEndian.PutUint64(tsBuf[:], uint64(e.Timestamp.UnixNano()))
	h.Write(tsBuf[:])
	return h.Sum(nil)
}

var idCounter int64

// nextID is deliberately simple for this increment — swap for a UUID/ULID
// generator without touching the hashing logic above, which only needs
// e.ID to be stable and included in the hash input.
func nextID() string {
	idCounter++
	return fmt.Sprintf("evt_%d_%d", time.Now().UTC().UnixNano(), idCounter)
}

// Package application implements AuditIngestion.EmitEvent
// (proto/audit/v1/audit.proto, doc 07 §7) with the hash-chaining scheme
// described in OpenBastion_06_Modele_Donnees.md §4 and Guide Sécurité §9:
// each event's hash covers its own fields plus the previous event's hash,
// so a retroactive edit anywhere in the chain is detectable.
package application

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// Store is the append-only persistence port. A PostgreSQL-backed
// implementation matching the partitioned audit_events table (doc 06 §3)
// is the natural next increment; nothing here depends on it directly.
type Store interface {
	Append(ctx context.Context, e *domain.Event) error
	Last(ctx context.Context) (*domain.Event, error) // nil, nil if the chain is empty
	All(ctx context.Context) ([]*domain.Event, error)
}

// AuditService computes the hash chain itself — a caller never supplies or
// even knows the previous hash, by design (doc 06 §4).
type AuditService struct {
	mu    sync.Mutex // serializes chain extension; a production deployment
	store Store      // would use a DB-level append lock instead of this
}

func NewAuditService(store Store) *AuditService {
	return &AuditService{store: store}
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

// EmitEvent appends one event to the chain. An event no emitter can mean is refused
// (domain.ErrInvalidEvent) before the chain is touched (ADR-0025).
func (s *AuditService) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) (*domain.Event, error) {
	if err := validate(actorID, action, resourceType, resourceID); err != nil {
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
		ID: nextID(), Timestamp: time.Now().UTC().Truncate(time.Microsecond), ActorID: actorID,
		Action: action, ResourceType: resourceType, ResourceID: resourceID,
		Success: success, PrevHash: prevHash,
	}
	e.Hash = computeHash(e)

	if err := s.store.Append(ctx, e); err != nil {
		return nil, err
	}
	return e, nil
}

// VerifyChain re-derives every event's hash from its own fields and
// prev_hash, and confirms each event correctly links to the next. This is
// the runnable form of "toute altération rétroactive... devient
// détectable" (doc 06 §4, Guide Sécurité §9) — not just a design claim.
func (s *AuditService) VerifyChain(ctx context.Context) error {
	events, err := s.store.All(ctx)
	if err != nil {
		return err
	}
	var prevHash []byte
	for i, e := range events {
		if want := computeHash(e); string(want) != string(e.Hash) {
			return fmt.Errorf("event %d (%s): hash does not match its own fields — tampered", i, e.ID)
		}
		if string(e.PrevHash) != string(prevHash) {
			return fmt.Errorf("event %d (%s): prev_hash does not match the preceding event — chain broken", i, e.ID)
		}
		prevHash = e.Hash
	}
	return nil
}

func computeHash(e *domain.Event) []byte {
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

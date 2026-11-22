package domain

import (
	"errors"
	"time"
)

// The independent head of a session's metadata (ADR-0116 §3): the Session Broker signs each revision
// of a session's row under a key it alone holds, and tells the Audit Service, for each, the session,
// the revision and the SHA-256 of the row's canonical form. The Audit Service writes that in its
// chain (session.metadata_attested) and keeps, per session, the last one, in the same transaction.
// A row restored to an earlier revision then disagrees with the head, whatever its MAC says. Nothing
// secret is here: an identifier, a number, a digest.

// ActionMetadataAttested is the chain's event of one attested revision.
const ActionMetadataAttested = "session.metadata_attested"

// MetadataHead is the last attested revision of a session, with what is needed to recompute the
// signed event it comes from, even once that event is archived out of the database (ADR-0032).
type MetadataHead struct {
	SessionID string
	Revision  uint64
	Digest    []byte // SHA-256 of the canonical form, 32 bytes
	KeyID     string // the Broker's HMAC key that signed the row (its identifier only)

	// The event: its identifier, time, previous hash, hash, chain key and hash version.
	EventID     string
	EventTime   time.Time
	PrevHash    []byte
	EventHash   []byte
	ChainKeyID  string
	HashVersion int
	Emitter     string
}

var (
	// ErrMetadataRollback: a revision older than the head — the row was taken back.
	ErrMetadataRollback = errors.New("this revision is older than the attested head: the session's row was rolled back")
	// ErrMetadataFork: the head's revision with another digest — the row was changed.
	ErrMetadataFork = errors.New("this revision was attested with another digest: the session's row was altered")
	// ErrMetadataGap: more than one revision ahead of the head (§5).
	ErrMetadataGap = errors.New("this revision is more than one ahead of the attested head")
	// ErrMetadataHeadTampered: the head does not recompute to the event the chain signed.
	ErrMetadataHeadTampered = errors.New("the attested head does not match the signed event it names")
)

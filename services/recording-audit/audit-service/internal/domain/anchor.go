package domain

import (
	"errors"
	"time"
)

// Anchor is a record, kept outside the database, of a head the chain has had (ADR-0028): the
// event that was last, its hash, and when — under an HMAC with the chain key, so that whoever
// can write where anchors are kept, but holds no key, cannot make one up.
type Anchor struct {
	EventID string
	Hash    []byte
	At      time.Time
	KeyID   string
	MAC     []byte
}

// ErrAnchorsUnavailable is returned when the anchors cannot be read: the chain cannot be
// vouched for, which is not the same as saying it was tampered with.
var ErrAnchorsUnavailable = errors.New("the anchors of the chain cannot be read")

// Checkpoint is a record, kept with the anchors (ADR-0032), that the events of the chain up to
// LastID were verified and then archived, out of the database, in Archive. Verification starts
// again from it: the first event left in the database must follow LastHash.
type Checkpoint struct {
	Archive        string // the archive's name, e.g. audit-2025-11.jsonl
	SHA256         []byte // of the archive file
	Count          int    // events in the archive
	FirstID        string
	PrevHash       []byte // the first archived event's prev_hash: the previous checkpoint's LastHash
	LastID         string
	LastHash       []byte
	LastVersion    int // hash version of the last archived event: versions do not go back after it
	AnchorsCovered int // how many anchors, from the first, name archived events
	At             time.Time
	KeyID          string
	MAC            []byte
}

// ErrArchiveRefused is returned when archiving stops rather than risk the evidence: a chain that
// does not verify, an archive that cannot be written or read back as written.
var ErrArchiveRefused = errors.New("archiving refused")

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

// Package domain holds the Audit Service's entities. See
// OpenBastion_06_Modele_Donnees.md §3 (audit_events) and §4 (hash chaining
// rationale).
package domain

import (
	"errors"
	"time"
)

// Event mirrors the audit_events table.
type Event struct {
	ID           string
	Timestamp    time.Time
	ActorID      string // empty for a system action
	Action       string
	ResourceType string
	ResourceID   string
	Success      bool
	PrevHash     []byte
	Hash         []byte

	// HashVersion says how Hash was computed (ADR-0026): HashV1 for the events written
	// before ADR-0026 (fields concatenated as they are), HashV2 for every event written
	// since (each field framed by its length). It is stored with the event and covered by
	// the v2 hash itself.
	HashVersion int
}

const (
	HashV1 = 1 // legacy: fields concatenated without framing — verified, never written
	HashV2 = 2 // current: a domain tag, then each field framed by its length
)

// ErrInvalidEvent is returned for an event no emitter can mean (ADR-0025): a field that is
// missing, too long, not UTF-8, carrying a control character, or an action or resource type
// outside their alphabet. Nothing of it is appended to the chain.
var ErrInvalidEvent = errors.New("invalid event")

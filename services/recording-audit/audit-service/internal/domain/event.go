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
}

// ErrInvalidEvent is returned for an event no emitter can mean (ADR-0025): a field that is
// missing, too long, not UTF-8, carrying a control character, or an action or resource type
// outside their alphabet. Nothing of it is appended to the chain.
var ErrInvalidEvent = errors.New("invalid event")

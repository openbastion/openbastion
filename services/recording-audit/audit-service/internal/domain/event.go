// Package domain holds the Audit Service's entities. See
// OpenBastion_06_Modele_Donnees.md §3 (audit_events) and §4 (hash chaining
// rationale).
package domain

import "time"

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

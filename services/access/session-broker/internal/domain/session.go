// Package domain holds the Session Broker's entities. See
// OpenBastion_06_Modele_Donnees.md §3 (sessions) and
// OpenBastion_07_Interfaces_Inter_Services.md §3 (SessionOrchestration).
package domain

import "time"

type SessionStatus string

const (
	StatusPendingApproval SessionStatus = "pending_approval" // unused in MVP — no Workflow Service yet (doc 04 §2)
	StatusActive          SessionStatus = "active"
	StatusExpired         SessionStatus = "expired"
	StatusTerminated      SessionStatus = "terminated"
	StatusDenied          SessionStatus = "denied"
)

// Session mirrors the sessions table.
type Session struct {
	ID                  string
	Status              SessionStatus
	Protocol            string
	RequestedBy         string
	PrivilegedAccountID string
	Justification       string
	CreatedAt           time.Time
	ExpiresAt           time.Time
	TerminatedAt        *time.Time
}

// EffectiveStatus returns Expired if the session is still marked Active
// but past ExpiresAt, without mutating the stored record — a lightweight
// stand-in for the Scheduler's expiration sweep (doc 04 §2 MVP scope:
// "Scheduler (expiration de session uniquement)"), which is not yet
// implemented as its own service.
func (s Session) EffectiveStatus(now time.Time) SessionStatus {
	if s.Status == StatusActive && now.After(s.ExpiresAt) {
		return StatusExpired
	}
	return s.Status
}

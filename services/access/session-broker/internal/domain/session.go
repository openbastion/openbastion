// Package domain holds the Session Broker's entities. See
// docs/architecture/data-architecture.md §3 (sessions) and
// docs/api/grpc/README.md §3 (SessionOrchestration).
package domain

import "time"

type SessionStatus string

const (
	// StatusPendingApproval is a break-glass request waiting for a second person
	// (ADR-0011). It is not a session yet: nothing can connect to it.
	StatusPendingApproval SessionStatus = "pending_approval"
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
	// ExpiresAt is the end of the session once it is active. While the request is
	// pending_approval it is instead the deadline for a decision (ADR-0011): a
	// pending request is not a session, and nothing reads it as one — connect
	// needs status active — so the one field serves both, and approval resets it
	// to decision time + DurationMinutes.
	ExpiresAt    time.Time
	TerminatedAt *time.Time

	// DurationMinutes is the length asked for. It is kept because a break-glass
	// session's clock starts at approval, not at the request (ADR-0011); zero on
	// rows that predate it.
	DurationMinutes int

	// DecidedBy is the user who approved or rejected a break-glass request, and
	// DecidedAt when. Empty for every session that did not go through a decision —
	// which is how the Broker tells an approved break-glass from one granted under
	// the earlier, one-person regime (ADR-0011, rule 7).
	DecidedBy string
	DecidedAt *time.Time

	// ApprovalRequired: an ordinary session on an account that requires another person's
	// approval (ADR-0067) — pending until decided, like a break-glass, under its own rules.
	// Ticket is the reference it was asked with; empty for a session that needed none.
	ApprovalRequired bool
	Ticket           string

	// AfterUseOwed: the session ended while active, and the Vault has not yet been told
	// (ADR-0044) — written with the end, cleared once the Vault has it.
	AfterUseOwed bool

	// BreakGlass marks a session that was authorised to run without the
	// recording guarantee if the recorder is down (ADR-0009). It says what the
	// session MAY do, not that it did: only the proxy knows whether the waiver
	// was actually used, and it says so in the audit trail (session.breakglass).
	BreakGlass bool
}

// EffectiveStatus returns Expired if the session is still marked Active — or a
// break-glass request still marked pending_approval — but past ExpiresAt,
// without mutating the stored record — a lightweight
// stand-in for the Scheduler's expiration sweep (docs/roadmap.md §2 MVP scope:
// "Scheduler (expiration de session uniquement)"), which is not yet
// implemented as its own service.
func (s Session) EffectiveStatus(now time.Time) SessionStatus {
	if (s.Status == StatusActive || s.Status == StatusPendingApproval) && now.After(s.ExpiresAt) {
		return StatusExpired
	}
	return s.Status
}

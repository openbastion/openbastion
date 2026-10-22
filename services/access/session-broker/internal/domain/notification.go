package domain

import "time"

// The events of an ApprovalNotification.
const (
	NotifyBreakGlassRequested = "breakglass.requested"
	NotifyBreakGlassApproved  = "breakglass.approved"
	NotifyBreakGlassRejected  = "breakglass.rejected"
)

// ApprovalNotification is what a notification may say. It names the request and the
// people; it deliberately has no field for the justification or for anything about
// the target — a notification travels to a channel whose readers may not be allowed
// to read those, and the detail is for whoever authenticates and holds the authority
// (GET /sessions?status=pending_approval). That is enforced by the shape of this
// struct, not by a promise in the adapters.
type ApprovalNotification struct {
	Event           string
	SessionID       string
	AccountID       string
	RequestedBy     string
	DecidedBy       string // empty for a request
	DurationMinutes int
	// ExpiresAt is the deadline for a decision while the request is pending, and the
	// end of the session once it has been approved.
	ExpiresAt time.Time
	At        time.Time
}

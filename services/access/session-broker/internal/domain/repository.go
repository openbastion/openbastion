package domain

import (
	"context"
	"errors"
	"time"
)

var ErrNotFound = errors.New("session not found")

// ErrRecordingUnavailable means the proxy refused to start the session because
// it could not be recorded (ADR-0008). It is the operator's answer to "why can't
// I connect?" — distinct from a conflict with the session's own state, and
// worth retrying shortly, which is why the API reports it as 503, not 409.
var ErrRecordingUnavailable = errors.New("recording unavailable")

// The errors a decision on a break-glass request (ADR-0011) can end in. The HTTP
// layer maps them to 403, 409 and 503; the message that accompanies each is the
// reason, safe to show a client. A dependency's own error never travels with
// ErrUnavailable to the client.
var (
	ErrForbidden           = errors.New("forbidden")
	ErrUnsupportedProtocol = errors.New("unsupported session protocol")
	ErrProtocolMismatch = errors.New("session protocol does not match the privileged account")
	ErrConflict            = errors.New("conflict")
	ErrUnavailable         = errors.New("a dependency is unavailable")

	// ErrTooManyPending is a break-glass request refused because its requester
	// already has as many waiting for a decision as the platform allows (ADR-0013).
	// The HTTP layer reports it as 429: it is the requester's own quota, and it
	// frees itself when one of their requests is decided or expires.
	ErrTooManyPending = errors.New("too many break-glass requests are waiting for a decision")

	// ErrAccountNotPinned is the Vault's refusal of a session on an account whose target's
	// host key is not pinned (ADR-0039), read from its stable code (ADR-0042). The message is
	// what the operator reads: what is wrong, and who can fix it.
	// ErrAccountNotFound: the Vault has no such (enabled) privileged account (ADR-0043).
	ErrAccountNotFound = errors.New("privileged account not found")

	ErrAccountNotPinned    = errors.New("the privileged account has no pinned host key: an administrator must pin it (PUT /vault/accounts/{id}/host-key) before any session")
	ErrAccountTLSNotPinned = errors.New("the graphical account has no pinned TLS certificate and target domain: an administrator must pin them (PUT /vault/accounts/{id}/tls-pin) before any session")

	// ErrInvalidTicket: the account requires approval (ADR-0067), and the request carries no
	// ticket, or one that does not follow the format the platform declared.
	ErrInvalidTicket = errors.New("this account requires approval: a ticket in the declared format is required")
)

type SessionRepository interface {
	Save(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)

	// SaveIfStatus replaces the stored session with s only if the stored one still
	// has status expected, and says whether it did — an atomic compare-and-swap.
	// It is what makes a decision on a break-glass request happen once: of two
	// decisions racing for the same pending request, exactly one swaps (ADR-0011).
	// An unknown id is not an error: it swaps nothing.
	SaveIfStatus(ctx context.Context, s *Session, expected SessionStatus) (swapped bool, err error)

	// ListPending returns the break-glass requests still waiting for a decision at
	// now — status pending_approval and a deadline (ExpiresAt) not before now, which is when
	// Session.EffectiveStatus still reads it as pending — soonest
	// deadline first, ties by id. At most limit are returned; more says there were
	// others (ADR-0012). It reads no secret and decides nothing: who may see which of
	// them is the service's question, not the store's.
	ListPending(ctx context.Context, now time.Time, limit int) (sessions []*Session, more bool, err error)

	// CountPending is how many break-glass requests requestedBy has waiting at now —
	// the same predicate as ListPending: status pending_approval, deadline not before
	// now (ADR-0013). It is an early, cheap answer; the limit itself is held by
	// SaveIfUnderPendingLimit.
	CountPending(ctx context.Context, requestedBy string, now time.Time) (int, error)

	// SaveIfUnderPendingLimit stores the pending request s only if its requester has
	// fewer than limit others waiting at now, and says whether it did. Counting and
	// storing are ONE atomic step: of any number of requests from the same requester
	// racing for the last place, exactly the places left are taken — whichever
	// Broker replica they reached (ADR-0013). Refusing is not an error: nothing is
	// written and saved is false.
	SaveIfUnderPendingLimit(ctx context.Context, s *Session, limit int, now time.Time) (saved bool, err error)

	// ExpireDue marks expired the active sessions and pending requests whose end
	// (ExpiresAt) is before now — at most limit, soonest end first — and returns them as
	// they now are (ADR-0034). Each is ONE atomic step: a session is expired by exactly one
	// call, whichever Broker replica made it, and a decision or a termination racing with
	// it either wins its compare-and-swap or loses it. What it expires is left "to be
	// audited" until MarkExpiryAudited.
	ExpireDue(ctx context.Context, now time.Time, limit int) ([]*Session, error)

	// ExpiriesToAudit returns the sessions expired before `before` whose expiry is not yet
	// in the audit trail, at most limit, oldest first.
	ExpiriesToAudit(ctx context.Context, before time.Time, limit int) ([]*Session, error)

	// MarkExpiryAudited records that the expiry of session id is in the audit trail.
	MarkExpiryAudited(ctx context.Context, id string) error

	// AfterUseOwed returns the sessions that ended before endedBefore and whose end the Vault
	// has not yet been told (ADR-0044), at most limit, oldest end first. ExpireDue sets the
	// debt of an active session it expires; a termination sets it with SaveIfStatus.
	AfterUseOwed(ctx context.Context, endedBefore time.Time, limit int) ([]AfterUseNotice, error)
	// MarkAfterUseDelivered records that the Vault has the end of session id.
	MarkAfterUseDelivered(ctx context.Context, id string) error
}

// AfterUseNotice is what the Vault is told when a session ends (ADR-0044).
type AfterUseNotice struct {
	SessionID, AccountID string
	EndedAt              time.Time
}

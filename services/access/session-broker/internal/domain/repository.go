package domain

import (
	"context"
	"errors"
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
	ErrForbidden   = errors.New("forbidden")
	ErrConflict    = errors.New("conflict")
	ErrUnavailable = errors.New("a dependency is unavailable")
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
}

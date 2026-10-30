// Package domain holds the Command Recorder's model: what a recorded
// command is, and what storing and reading recordings requires of a
// repository. It depends on nothing else in the service.
package domain

import (
	"context"
	"errors"
	"time"
)

var (
	// ErrInvalidEntry is returned for a batch the recorder refuses as a
	// whole: an entry with no session, no command or no timestamp.
	ErrInvalidEntry = errors.New("invalid command entry")

	// ErrNotASessionID is returned for a read of an id that cannot be a session's: empty,
	// longer than a stored session id may be, or not UTF-8 (ADR-0024). The answer is the
	// same for everyone, before anything is asked or written.
	ErrNotASessionID = errors.New("not a session id")

	// ErrForbidden is returned when the caller may not read a recording: no
	// authenticated user was named, or RBAC denied it.
	ErrForbidden = errors.New("access denied")

	// ErrUnavailable is returned when a read could not be decided or recorded
	// because a dependency did not answer — the Authorization Service, or the
	// Audit Service that must hold the read before it is served (ADR-0022). It
	// is not a refusal: the same read, once the dependency is back, is served.
	ErrUnavailable = errors.New("unavailable")
)

// CommandEntry is one command an operator submitted in a session — the
// record behind proto/recording/v1/recording.proto's CommandEntry and the
// session_command_entries table (doc 06 §3).
type CommandEntry struct {
	// ID is assigned by the store, in insertion order. It breaks ties
	// between entries with the same timestamp, so a replay keeps the order
	// the commands were recorded in.
	ID        int64
	SessionID string
	Timestamp time.Time
	Command   string
}

// CommandRepository is append-only by design: a recording is evidence, and
// nothing in this service — no method here, no endpoint above it — updates
// or deletes an entry. Retention, when it comes, is a decision about whole
// recordings, made outside the request path.
type CommandRepository interface {
	// AppendBatch stores every entry, or none: a failure part-way must not
	// leave half a batch recorded.
	AppendBatch(ctx context.Context, entries []CommandEntry) error

	// ListBySession returns one page of a session's entries ordered by
	// (Timestamp, ID), and the total number of entries the session has.
	// A session with no entries is an empty page, not an error.
	ListBySession(ctx context.Context, sessionID string, page, pageSize int) ([]CommandEntry, int, error)
}

// ReadinessChecker is implemented by a repository that can tell whether it
// could take a write right now. It is separate from CommandRepository because
// not every store has anything to check (the in-memory one never fails), and
// because it answers a different question from liveness: a recorder whose
// process is up but whose database is unreachable, or read-only after a
// failover, must report NOT ready — the proxies' record-or-refuse policy
// (ADR-0008) refuses sessions on exactly that signal.
type ReadinessChecker interface {
	Ready(ctx context.Context) error
}

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

	// ErrForbidden is returned when the caller may not read a recording —
	// denied by RBAC, or the Authorization Service could not be asked
	// (fail-closed).
	ErrForbidden = errors.New("access denied")
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

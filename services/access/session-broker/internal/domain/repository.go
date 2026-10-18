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

type SessionRepository interface {
	Save(ctx context.Context, s *Session) error
	Get(ctx context.Context, id string) (*Session, error)
}

package domain

import (
	"context"
	"errors"
	"time"
)

var (
	ErrInvalidSegment = errors.New("invalid video segment")
	ErrAlreadyExists  = errors.New("video recording already exists")
	ErrConflict       = errors.New("video recording sequence conflict")
	ErrNotFound       = errors.New("video segment not found")
	ErrForbidden      = errors.New("video recording access denied")
	ErrUnavailable    = errors.New("video recording dependency unavailable")
	ErrIntegrity      = errors.New("video recording integrity check failed")
)

type VideoFrame struct {
	Timestamp time.Time `json:"timestamp"`
	Data      []byte    `json:"data"`
	Codec     string    `json:"codec"`
}

type VideoSegment struct {
	SessionID               string       `json:"session_id"`
	FirstSequence           int64        `json:"first_sequence"`
	LastSequence            int64        `json:"last_sequence"`
	Frames                  []VideoFrame `json:"frames"`
	Terminal                bool         `json:"terminal"`
	TerminalThroughSequence int64        `json:"terminal_through_sequence"`
}

type SegmentMetadata struct {
	SessionID     string
	FirstSequence int64
	LastSequence  int64
	ObjectKey     string
	SHA256        []byte
}

type StoredSegment struct {
	SegmentMetadata
	KeyID      string
	WrappedDEK []byte
	Complete   bool
}

type Repository interface {
	BeginRecording(ctx context.Context, sessionID, keyID string, wrappedDEK []byte) error
	AppendSegment(ctx context.Context, segment SegmentMetadata) error
	CompleteRecording(ctx context.Context, sessionID string, throughSequence int64) error
	GetSegment(ctx context.Context, sessionID string, firstSequence int64) (StoredSegment, error)
	// GetSegmentsFrom returns, in order, at most limit segments of the session whose first
	// sequence is firstSequence or later (ADR-0093): the caller keeps the run without a gap.
	GetSegmentsFrom(ctx context.Context, sessionID string, firstSequence int64, limit int) ([]StoredSegment, error)
	Ready(ctx context.Context) error
}

type ObjectStore interface {
	Put(ctx context.Context, key string, ciphertext []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
	Ready(ctx context.Context) error
}

type KeyWrapper interface {
	KeyID() string
	Wrap(ctx context.Context, dek, aad []byte) ([]byte, error)
	Unwrap(ctx context.Context, wrapped, aad []byte) ([]byte, error)
	Ready(ctx context.Context) error
}

type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error)
}

type AuditEmitter interface {
	// details are the event's bounded details (ADR-0068), nil for none: the range a read served.
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool, details map[string]string) error
}

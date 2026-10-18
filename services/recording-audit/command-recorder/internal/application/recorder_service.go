// Package application holds the Command Recorder's use cases: accepting
// batches of captured commands from a protocol proxy, and serving a
// session's recording to someone authorized to read it.
package application

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// AuthorizationClient asks the Authorization Service (RBAC) whether a set
// of roles may perform an action on a resource.
type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (allowed bool, reason string, err error)
}

const (
	// ActionRead is the RBAC action required to read a session's recording.
	ActionRead = "recording:session:read"

	// MaxBatchSize bounds one Record call. A proxy sends small batches; this
	// only stops one request from holding a transaction open indefinitely.
	MaxBatchSize = 1000

	// MaxCommandBytes bounds one stored command. The Recording Tap already
	// truncates to this size; the recorder enforces it too, because it must
	// not trust its caller to have done so.
	MaxCommandBytes = 8192

	maxSessionIDBytes = 256

	// Pagination mirrors doc 05's Page/PageSize parameters
	// (pageSize: min 1, max 100, default 20).
	minPage         = 1
	minPageSize     = 1
	maxPageSize     = 100
	defaultPageSize = 20
)

// RecordingResource is the RBAC resource naming one session's recording.
// A policy granting an auditor role "recording:session:*" lets it read every
// recording; a narrower pattern limits it to some.
func RecordingResource(sessionID string) string { return "recording:session:" + sessionID }

type RecorderService struct {
	repo  domain.CommandRepository
	authz AuthorizationClient
}

func NewRecorderService(repo domain.CommandRepository, authz AuthorizationClient) *RecorderService {
	return &RecorderService{repo: repo, authz: authz}
}

// Ready reports whether the service could durably record a batch right now.
// It is what GET /readyz answers, and what a proxy asks before it admits a
// session it is required to record (ADR-0008). A store with nothing to check
// is always ready.
func (s *RecorderService) Ready(ctx context.Context) error {
	if c, ok := s.repo.(domain.ReadinessChecker); ok {
		return c.Ready(ctx)
	}
	return nil
}

// Record validates and stores a batch of captured commands, returning how
// many were stored. The batch is all-or-nothing: one invalid entry refuses
// the whole batch (domain.ErrInvalidEntry) so the caller learns about it,
// rather than part of a session being recorded silently.
//
// There is no RBAC check here, deliberately: the caller is a protocol proxy,
// not a user, and this endpoint is internal — it is not routed by the API
// Gateway. What stops a reachable-but-hostile caller from forging entries
// into a recording is the network boundary and internal mutual TLS (Guide
// Sécurité), which this slice does not have yet; see NOTES_SANDBOX.md.
//
// Commands are normalized, not rejected, when they are merely awkward:
// invalid UTF-8 is replaced, NUL bytes are dropped, and an over-long command
// is truncated on a character boundary — so a replay is always valid text,
// and one odd command never costs the rest of its batch. Timestamps are
// truncated to microseconds, the precision PostgreSQL stores and the
// precision a command's ciphertext is bound to: the value sealed must be the
// value read back.
func (s *RecorderService) Record(ctx context.Context, entries []domain.CommandEntry) (int, error) {
	if len(entries) == 0 {
		return 0, fmt.Errorf("%w: empty batch", domain.ErrInvalidEntry)
	}
	if len(entries) > MaxBatchSize {
		return 0, fmt.Errorf("%w: batch of %d entries exceeds the maximum of %d", domain.ErrInvalidEntry, len(entries), MaxBatchSize)
	}

	clean := make([]domain.CommandEntry, 0, len(entries))
	for i, e := range entries {
		if e.SessionID == "" || len(e.SessionID) > maxSessionIDBytes {
			return 0, fmt.Errorf("%w: entry %d has no usable session id", domain.ErrInvalidEntry, i)
		}
		if e.Timestamp.IsZero() {
			return 0, fmt.Errorf("%w: entry %d has no timestamp", domain.ErrInvalidEntry, i)
		}
		command := normalizeCommand(e.Command)
		if command == "" {
			return 0, fmt.Errorf("%w: entry %d has an empty command", domain.ErrInvalidEntry, i)
		}
		clean = append(clean, domain.CommandEntry{
			SessionID: e.SessionID,
			Timestamp: e.Timestamp.UTC().Truncate(time.Microsecond),
			Command:   command,
		})
	}

	if err := s.repo.AppendBatch(ctx, clean); err != nil {
		return 0, err
	}
	return len(clean), nil
}

func normalizeCommand(c string) string {
	c = strings.ToValidUTF8(c, "�")
	c = strings.ReplaceAll(c, "\x00", "")
	c = strings.TrimSpace(c)
	if len(c) > MaxCommandBytes {
		cut := MaxCommandBytes
		for cut > 0 && !utf8.RuneStart(c[cut]) {
			cut--
		}
		c = c[:cut]
	}
	return c
}

// GetRecording returns one page of a session's recording, in the order the
// commands were recorded, and the total number of entries.
//
// RBAC runs first. A session with no entries is an empty page, never a
// "not found": the recorder does not know which sessions exist, and an
// answer that depended on it would let an unauthorized caller probe for
// session ids — which the order of checks (403 before anything else)
// already rules out.
func (s *RecorderService) GetRecording(ctx context.Context, actorRoles []string, sessionID string, page, pageSize int) ([]domain.CommandEntry, int, error) {
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, RecordingResource(sessionID), ActionRead)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: checking access (fail-closed): %v", domain.ErrForbidden, err)
	}
	if !allowed {
		return nil, 0, fmt.Errorf("%w: %s", domain.ErrForbidden, reason)
	}

	page, pageSize = ClampPage(page, pageSize)
	return s.repo.ListBySession(ctx, sessionID, page, pageSize)
}

// ClampPage is the pagination rule GetRecording applies (page < 1 → 1;
// pageSize < 1 → the default; pageSize > 100 → 100). It is exported so the
// HTTP layer can report the page and page size actually SERVED, not the ones
// the caller asked for.
func ClampPage(page, pageSize int) (int, int) {
	if page < minPage {
		page = minPage
	}
	if pageSize < minPageSize {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

// Package application holds the Command Recorder's use cases: accepting
// batches of captured commands from a protocol proxy, and serving a
// session's recording to someone authorized to read it.
package application

import (
	"context"
	"fmt"
	"log"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/openbastion/openbastion/pkg/refusalbudget"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// AuthorizationClient asks the Authorization Service (RBAC) whether a set
// of roles may perform an action on a resource.
type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (allowed bool, reason string, err error)
}

// AuditEmitter is the port to AuditIngestion (proto/audit/v1/audit.proto): the same call the
// Session Broker and the proxies make.
type AuditEmitter interface {
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error
}

// AuditActionRead is the audit action of a recording that was read (ADR-0022). The event is
// about the session the recording is of (resource_type "session", resource_id its id), so a
// search for one session finds who opened it, who read its record (session.read) and who
// read what was typed in it.
const AuditActionRead = "recording.read"

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

// What the refused reads of a recording by one user may write to the audit (ADR-0024): the
// shared budget's strict defaults and bounds (pkg/refusalbudget).
const (
	DefaultReadAuditBurst         = refusalbudget.DefaultBurst
	DefaultReadAuditRatePerMinute = refusalbudget.DefaultRatePerMinute
	MaxReadAuditBurst             = refusalbudget.MaxBurst
	MaxReadAuditRatePerMinute     = refusalbudget.MaxRatePerMinute
)

type RecorderService struct {
	repo  domain.CommandRepository
	authz AuthorizationClient
	audit AuditEmitter

	// readRefusals bounds what the refused reads of one identity write to the audit
	// (ADR-0024). Never nil: the constructor gives the strict default.
	readRefusals *refusalbudget.Budget
}

func NewRecorderService(repo domain.CommandRepository, authz AuthorizationClient, audit AuditEmitter) *RecorderService {
	return &RecorderService{repo: repo, authz: authz, audit: audit, readRefusals: refusalbudget.New(0, 0)}
}

// WithReadRefusalAudit sets the budget of what the refused reads of one identity write to
// the audit (ADR-0024): `burst` at once, then `perMinute` a minute. Zero or negative keeps
// the default: there is no way to ask for "everything" or for "nothing", and a Recorder
// built by hand without this call is strict.
func (s *RecorderService) WithReadRefusalAudit(burst, perMinute int) *RecorderService {
	s.readRefusals = refusalbudget.New(burst, perMinute)
	return s
}

// WithClock replaces the clock of the refusal budget; for tests.
func (s *RecorderService) WithClock(now func() time.Time) *RecorderService {
	s.readRefusals.WithClock(now)
	return s
}

// ReadRefusalAudit says the budget really applied, for the line written at start-up.
func (s *RecorderService) ReadRefusalAudit() (burst, perMinute int) {
	return s.readRefusals.Burst(), s.readRefusals.RatePerMinute()
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
// callerID and actorRoles are the Gateway's — the verified user and the
// roles of their token, never the client's (ADR-0022). The order is: an id that
// cannot be a session (ErrNotASessionID), a caller with no name (ErrForbidden),
// RBAC (ErrForbidden, and a refusal is an event within the caller's budget —
// ADR-0024; ErrUnavailable when the Authorization Service does not answer —
// fail-closed, and not called a refusal), the store, the audit, then the page
// is served.
//
// A recording is what was typed in a session, and every read of it is served
// on the strength of a policy: there is no requester exception here, the
// operator does not read their own recording. So every page served is an
// audit event, recording.read, under the caller's name, written BEFORE it is
// served — and a page that could not be recorded as read is not served
// (ErrUnavailable): ADR-0021's rule for what discloses. There is no budget:
// a suppressed event is a read nobody can prove.
//
// A session with no entries is an empty page, never a "not found": the
// recorder does not know which sessions exist, and an answer that depended on
// it would let an unauthorized caller probe for session ids — which the order
// of checks (403 before anything else) already rules out. An empty page is a
// read like another, and is on the record like another.
func (s *RecorderService) GetRecording(ctx context.Context, callerID string, actorRoles []string, sessionID string, page, pageSize int) ([]domain.CommandEntry, int, error) {
	// What cannot be a session — the bound Record applies — is refused before anything: it
	// is the same answer for everyone, and no read of it, served or refused, may write a
	// string the caller chose into the signed trail (ADR-0024).
	if !usableSessionID(sessionID) {
		return nil, 0, domain.ErrNotASessionID
	}
	if callerID == "" {
		return nil, 0, fmt.Errorf("%w: reading a recording needs an authenticated user", domain.ErrForbidden)
	}
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, RecordingResource(sessionID), ActionRead)
	if err != nil {
		return nil, 0, fmt.Errorf("%w (asking the Authorization Service: %v)", domain.ErrUnavailable, err)
	}
	if !allowed {
		// The refusal is on the record (ADR-0024), within the caller's budget, and it is the
		// same refusal whatever the budget or the audit says.
		s.auditRefusedRead(ctx, callerID, sessionID)
		return nil, 0, fmt.Errorf("%w: %s", domain.ErrForbidden, reason)
	}

	page, pageSize = ClampPage(page, pageSize)
	entries, total, err := s.repo.ListBySession(ctx, sessionID, page, pageSize)
	if err != nil {
		return nil, 0, err
	}
	// The store is read first so that an event is only written for a page that is about to
	// be served; the page is held here, not handed over, until the event is written.
	if err := s.audit.EmitEvent(ctx, callerID, AuditActionRead, "session", sessionID, true); err != nil {
		return nil, 0, fmt.Errorf("%w (recording the read: %v)", domain.ErrUnavailable, err)
	}
	return entries, total, nil
}

// usableSessionID is what a read may name (ADR-0024, ADR-0025): 1 to 256 bytes of UTF-8
// without a control character — the bounds the Audit Service holds an identifier to, so that
// nothing the Recorder would write is refused there.
func usableSessionID(id string) bool {
	if id == "" || len(id) > maxSessionIDBytes || !utf8.ValidString(id) {
		return false
	}
	for _, c := range id {
		if unicode.IsControl(c) {
			return false
		}
	}
	return true
}

// auditRefusedRead writes the refusal of a read to the audit, under the name of the one who
// asked — the verified identity the Gateway named — when that identity's budget allows it
// (ADR-0024, the rule of ADR-0020). It is best effort: there is nothing for an audit that is
// down to prevent, the read is refused anyway; the failure is in this log, which the caller
// is not told.
func (s *RecorderService) auditRefusedRead(ctx context.Context, callerID, sessionID string) {
	write, firstUnwritten := s.readRefusals.Take(callerID)
	if !write {
		if firstUnwritten {
			log.Printf("command-recorder: refused reads of recordings by user %s are no longer written to the audit one by one (budget spent)", callerID)
		}
		return
	}
	if err := s.audit.EmitEvent(ctx, callerID, AuditActionRead, "session", sessionID, false); err != nil {
		log.Printf("command-recorder: the refusal of a read of the recording of %s by user %s could not be audited: %v", sessionID, callerID, err)
	}
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

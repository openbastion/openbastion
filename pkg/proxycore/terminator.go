package proxycore

import "context"

// AuditEmitter is the minimal interface the Session Terminator needs
// against the Audit Service (proto/audit/v1/audit.proto, EmitEvent).
type AuditEmitter interface {
	EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error
}

// Terminator ends a session deterministically: it always purges the
// credential first, then emits the audit event — in that order, so an
// audit failure can never leave a credential un-purged, and a purge can
// never happen without a corresponding audit trail entry (doc 06 §4,
// Guide Sécurité §8).
type Terminator struct {
	audit AuditEmitter
}

func NewTerminator(audit AuditEmitter) *Terminator {
	return &Terminator{audit: audit}
}

// Terminate purges cred and records the outcome.
func (t *Terminator) Terminate(ctx context.Context, sessionID string, cred *Credential, success bool) error {
	cred.Purge()
	return t.audit.EmitEvent(ctx, "session.terminate", "session", sessionID, success)
}

// EmitConnectFailure records a session that never obtained a credential —
// there is nothing to purge, but the failed attempt is still audited
// (Full Auditability, doc 00 §2 — a failure is never a silent gap).
func (t *Terminator) EmitConnectFailure(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.connect", "session", sessionID, false)
}

// EmitRecordingUnavailable records a session REFUSED because the recorder
// could not take it (ADR-0008): no credential was fetched, nothing ran on the
// target. A dedicated action, not session.connect/false, so an auditor can
// list exactly the sessions the recording policy stopped.
func (t *Terminator) EmitRecordingUnavailable(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.recording_unavailable", "session", sessionID, false)
}

// EmitRecordingLost records a session TERMINATED mid-way because a command
// could not be recorded. It is emitted in addition to session.terminate, which
// still says the session ended and that it did not end cleanly.
func (t *Terminator) EmitRecordingLost(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.recording_lost", "session", sessionID, false)
}

// EmitBreakGlass records that a session was admitted WITHOUT a recorder, by a
// break-glass waiver (ADR-0009). It is emitted before the credential is fetched
// and its failure refuses the session, so a waiver is never exercised unseen.
func (t *Terminator) EmitBreakGlass(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.breakglass", "session", sessionID, true)
}

// EmitExpired records a session cut by the proxy at the end of its allotted
// time. It is a normal end (success), emitted in addition to session.terminate.
func (t *Terminator) EmitExpired(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.expire", "session", sessionID, true)
}

// EmitRevoked records a connection the proxy cut because the Session Broker told
// it the session was ended (ADR-0018). It is emitted in addition to
// session.terminate, which says the connection ended and that its credential was
// purged; this one says why. The person who ended the session is named by the
// Broker's own event, not here: the proxy only knows that it was told to.
func (t *Terminator) EmitRevoked(ctx context.Context, sessionID string) error {
	return t.audit.EmitEvent(ctx, "session.revoked", "session", sessionID, true)
}

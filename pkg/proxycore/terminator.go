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

package proxycore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"
)

// ErrSessionExpired marks a session that ran to the end of its allotted time
// and was cut there by the proxy. It is a normal end, not a failure: callers
// use errors.Is to tell the operator why the connection closed.
var ErrSessionExpired = errors.New("session expired")

// SessionMetadata is what the Session Broker hands to a proxy via
// ProxyControl.EstablishSession (proto/proxy/v1/proxy_control.proto) —
// deliberately free of any secret material.
type SessionMetadata struct {
	SessionID  string
	TargetHost string
	ScopeToken string

	// ExpiresAt is the end of the session. The proxy cuts the session there
	// (ErrSessionExpired); the zero value means no limit, for callers that
	// enforce one elsewhere.
	ExpiresAt time.Time

	// BreakGlass is the Session Broker's authorisation for a recording waiver
	// (ADR-0009). It is a request the proxy honours only when it has itself been
	// configured to (RecordingConfig.BreakGlass) and the recorder is not ready.
	BreakGlass bool

	// Admission, when it is a granted admission for this very session, spares
	// Serve from asking again: a caller that had to decide earlier (which tap to
	// build depends on it) passes its decision along. An absent or foreign
	// admission is ignored and Serve admits the session itself.
	Admission Admission
}

// Listener drives one session through the shared pipeline: fetch
// credential, relay via the protocol-specific Codec, then terminate and
// purge. It is intentionally protocol-agnostic — everything protocol-
// specific lives behind Codec.
type Listener struct {
	Fetcher    *CredentialFetcher
	Terminator *Terminator

	// Recording is what happens to a session that cannot be recorded
	// (ADR-0008). Its zero value is RecordingRequired with no recorder, which
	// refuses every session: a Listener nobody configured never runs
	// unrecorded. Best-effort must be asked for.
	Recording RecordingConfig
}

func NewListener(fetcher *CredentialFetcher, terminator *Terminator) *Listener {
	return &Listener{Fetcher: fetcher, Terminator: terminator}
}

// Admit decides whether a session may start, before anything irreversible
// happens. Under RecordingRequired it refuses — and audits the refusal as
// session.recording_unavailable — when the recorder is not ready. It never
// grants a break-glass waiver: that needs AdmitSession.
func (l *Listener) Admit(ctx context.Context, sessionID string) error {
	_, err := l.AdmitSession(ctx, sessionID, false)
	return err
}

// AdmitSession is Admit that can also grant a break-glass waiver (ADR-0009):
// when the recorder is not ready and the session asked for one, and this proxy
// has been configured to allow it, the session is admitted — after the waiver has
// been audited as session.breakglass. If that event cannot be recorded the
// session is refused: a waiver nobody can see is not granted. A ready recorder
// always wins — the waiver is for need, and never degrades a session that could
// have been recorded.
func (l *Listener) AdmitSession(ctx context.Context, sessionID string, breakGlass bool) (Admission, error) {
	err := l.Recording.Admit(ctx)
	if err == nil {
		return Admission{sessionID: sessionID, granted: true}, nil
	}
	if breakGlass && l.Recording.canWaive() {
		if aerr := l.Terminator.EmitBreakGlass(ctx, sessionID); aerr != nil {
			_ = l.Terminator.EmitRecordingUnavailable(ctx, sessionID)
			return Admission{}, fmt.Errorf("%w: break-glass refused, it could not be audited: %v", ErrRecordingUnavailable, aerr)
		}
		return Admission{sessionID: sessionID, granted: true, waived: true}, nil
	}
	_ = l.Terminator.EmitRecordingUnavailable(ctx, sessionID)
	return Admission{}, err
}

// Probe is the early, non-binding version of AdmitSession, for a proxy's control
// plane that wants to refuse before issuing a ticket. It audits a refusal like
// AdmitSession does, but a waiver that would be granted is NOT audited here — the
// event belongs to the moment the waiver is actually used, when Serve admits.
func (l *Listener) Probe(ctx context.Context, sessionID string, breakGlass bool) error {
	err := l.Recording.Admit(ctx)
	if err == nil {
		return nil
	}
	if breakGlass && l.Recording.canWaive() {
		return nil
	}
	_ = l.Terminator.EmitRecordingUnavailable(ctx, sessionID)
	return err
}

// Serve runs one session end-to-end. The caller supplies the Codec and the
// already-connected client/target streams; Serve owns the credential
// lifecycle and guarantees Purge runs exactly once, on every exit path.
func (l *Listener) Serve(ctx context.Context, meta SessionMetadata, codec Codec, client, target io.ReadWriter) error {
	// Before the credential: a Vault scope token is single-use, so fetching it
	// for a session that is then refused would burn it for nothing.
	if !meta.Admission.For(meta.SessionID) {
		if _, err := l.AdmitSession(ctx, meta.SessionID, meta.BreakGlass); err != nil {
			return err
		}
	}

	cred, err := l.Fetcher.Fetch(ctx, meta.ScopeToken)
	if err != nil {
		_ = l.Terminator.EmitConnectFailure(ctx, meta.SessionID)
		return err
	}

	// The session ends when its time does. The relay runs under a deadline; the
	// audit and the purge below do NOT — they use the caller's context, which is
	// still alive when the deadline fires.
	relayCtx := ctx
	if !meta.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		relayCtx, cancel = context.WithDeadline(ctx, meta.ExpiresAt)
		defer cancel()
	}

	relayErr := codec.Relay(relayCtx, client, target, cred)
	expired := relayErr != nil && ctx.Err() == nil && errors.Is(relayCtx.Err(), context.DeadlineExceeded)
	if expired {
		_ = l.Terminator.EmitExpired(ctx, meta.SessionID)
		relayErr = ErrSessionExpired
	}
	if errors.Is(relayErr, ErrRecordingUnavailable) {
		_ = l.Terminator.EmitRecordingLost(ctx, meta.SessionID)
	}
	termErr := l.Terminator.Terminate(ctx, meta.SessionID, cred, relayErr == nil || expired)
	if relayErr != nil {
		return relayErr
	}
	return termErr
}

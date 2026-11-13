package proxycore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/openbastion/openbastion/pkg/screenstream"
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

	// ScreenProtocol is set only for ServeScreen and comes from the privileged account, never the client.
	ScreenProtocol screenstream.Protocol

	// ExpiresAt is the end of the session. The proxy cuts the session there
	// (ErrSessionExpired); the zero value means no limit, for callers that
	// enforce one elsewhere.
	ExpiresAt time.Time

	// BreakGlass is the Session Broker's authorisation for a recording waiver
	// (ADR-0009). It is a request the proxy honours only when it has itself been
	// configured to (RecordingConfig.BreakGlass) and the recorder is not ready.
	BreakGlass bool

	// ClipboardToTarget and ClipboardFromTarget are the clipboard directions the Session
	// Broker granted at creation (ADR-0096 §1), each its own right; false is refused. Only
	// an RDP screen session carries them: the proxy refuses them for any other protocol.
	ClipboardToTarget, ClipboardFromTarget bool

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

	// Live is the registry of the connections this listener serves, which is what
	// lets the Session Broker end a session that is already open (ADR-0018). The
	// proxy's control plane shares it: the route that revokes a session and the
	// pipeline that serves it must be talking about the same connections.
	// NewListener creates one; a Listener without it refuses every session
	// (ErrNotRevocable): a connection nobody could cut is not started.
	Live *LiveSessions

	// ScreenInput bounds a graphical session's input, ScreenAckTimeout how long the Video
	// Recorder has to acknowledge one frame before the recording counts as lost (ADR-0071).
	// Zero means the defaults.
	ScreenInput      ScreenInputLimits
	ScreenAckTimeout time.Duration
	// Clipboard audits the clipboard's transfers (ADR-0096). Nil, no screen session opens its
	// clipboard, whatever its rights.
	Clipboard ClipboardAuditor
}

func NewListener(fetcher *CredentialFetcher, terminator *Terminator) *Listener {
	return &Listener{Fetcher: fetcher, Terminator: terminator, Live: NewLiveSessions()}
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
// already-connected client/target streams; Serve owns the credential lifecycle
// and guarantees Purge runs exactly once, on every exit path.
func (l *Listener) Serve(ctx context.Context, meta SessionMetadata, codec Codec, client, target io.ReadWriter) error {
	return l.serveWithRelay(ctx, meta, nil, func(relayCtx, _ context.Context, cred *Credential) error {
		return codec.Relay(relayCtx, client, target, cred)
	})
}

// serveWithRelay is the lifecycle shared by SSH and graphical sessions. The
// admission hook is evaluated after Live.Begin but before fetching the single-use
// Vault scope; relay cleanup and audit use the caller context, not the deadline.
func (l *Listener) serveWithRelay(ctx context.Context, meta SessionMetadata, admit func(context.Context, SessionMetadata) (Admission, error), relay func(context.Context, context.Context, *Credential) error) error {
	if l.Live == nil {
		return ErrNotRevocable
	}
	liveCtx, cancelLive := context.WithCancelCause(ctx)
	defer cancelLive(nil)
	// A session the Broker has ended is refused before admission, audit or
	// credential fetch. Registering first makes every accepted connection cuttable.
	conn, err := l.Live.Begin(meta.SessionID, cancelLive)
	if err != nil {
		return err
	}
	defer conn.End()
	// The first cancellation cause wins: a caller that stopped before a later
	// revocation is not misreported as revoked.
	revoked := func() bool { return errors.Is(context.Cause(liveCtx), ErrSessionRevoked) }

	// A Vault scope is single-use. Admission must happen before fetching it, or a
	// session refused by recording policy would burn a ticket for nothing.
	if !meta.Admission.For(meta.SessionID) {
		if admit != nil {
			meta.Admission, err = admit(ctx, meta)
		} else {
			meta.Admission, err = l.AdmitSession(ctx, meta.SessionID, meta.BreakGlass)
		}
		if err != nil {
			return err
		}
	}

	cred, err := l.Fetcher.Fetch(liveCtx, meta.ScopeToken)
	if err != nil {
		if revoked() {
			// A cut during fetch is not a failed connection attempt.
			return ErrSessionRevoked
		}
		_ = l.Terminator.EmitConnectFailure(ctx, meta.SessionID)
		return err
	}
	if revoked() {
		// The cut landed between fetch and relay: purge the credential and never
		// contact the target.
		_ = l.Terminator.EmitRevoked(ctx, meta.SessionID)
		_ = l.Terminator.Terminate(ctx, meta.SessionID, cred, true)
		return ErrSessionRevoked
	}

	// The relay ends at the session deadline. Audit and purge use the caller's
	// context so they still run after the deadline fires.
	relayCtx := liveCtx
	if !meta.ExpiresAt.IsZero() {
		var cancel context.CancelFunc
		relayCtx, cancel = context.WithDeadline(liveCtx, meta.ExpiresAt)
		defer cancel()
	}

	relayErr := relay(relayCtx, ctx, cred)
	// The relay returned and the target is closed: revocation may now complete.
	conn.RelayEnded()
	cut := revoked()
	expired := relayErr != nil && ctx.Err() == nil && !cut && errors.Is(relayCtx.Err(), context.DeadlineExceeded)
	if cut {
		_ = l.Terminator.EmitRevoked(ctx, meta.SessionID)
		relayErr = ErrSessionRevoked
	}
	if expired {
		_ = l.Terminator.EmitExpired(ctx, meta.SessionID)
		relayErr = ErrSessionExpired
	}
	if errors.Is(relayErr, ErrRecordingUnavailable) || errors.Is(relayErr, ErrRecordingLost) {
		_ = l.Terminator.EmitRecordingLost(ctx, meta.SessionID)
	}
	if errors.Is(relayErr, ErrHostKeyMismatch) {
		_ = l.Terminator.EmitHostKeyMismatch(ctx, meta.SessionID)
	}
	if isTLSPinMismatch(relayErr) {
		_ = l.Terminator.EmitTLSCertificateMismatch(ctx, meta.SessionID)
	}
	termErr := l.Terminator.Terminate(ctx, meta.SessionID, cred, relayErr == nil || expired || cut)
	if relayErr != nil {
		return relayErr
	}
	return termErr
}

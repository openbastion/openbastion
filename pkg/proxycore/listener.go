package proxycore

import (
	"context"
	"errors"
	"io"
	"time"
)

// SessionMetadata is what the Session Broker hands to a proxy via
// ProxyControl.EstablishSession (proto/proxy/v1/proxy_control.proto) —
// deliberately free of any secret material.
type SessionMetadata struct {
	SessionID  string
	TargetHost string
	ScopeToken string
	ExpiresAt  time.Time
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
// session.recording_unavailable — when the recorder is not ready. Serve calls
// it first, so no path to a credential fetch bypasses it; a proxy's control
// plane may call it earlier still, to refuse before even issuing a ticket.
func (l *Listener) Admit(ctx context.Context, sessionID string) error {
	if err := l.Recording.Admit(ctx); err != nil {
		_ = l.Terminator.EmitRecordingUnavailable(ctx, sessionID)
		return err
	}
	return nil
}

// Serve runs one session end-to-end. The caller supplies the Codec and the
// already-connected client/target streams; Serve owns the credential
// lifecycle and guarantees Purge runs exactly once, on every exit path.
func (l *Listener) Serve(ctx context.Context, meta SessionMetadata, codec Codec, client, target io.ReadWriter) error {
	// Before the credential: a Vault scope token is single-use, so fetching it
	// for a session that is then refused would burn it for nothing.
	if err := l.Admit(ctx, meta.SessionID); err != nil {
		return err
	}

	cred, err := l.Fetcher.Fetch(ctx, meta.ScopeToken)
	if err != nil {
		_ = l.Terminator.EmitConnectFailure(ctx, meta.SessionID)
		return err
	}

	relayErr := codec.Relay(ctx, client, target, cred)
	if errors.Is(relayErr, ErrRecordingUnavailable) {
		_ = l.Terminator.EmitRecordingLost(ctx, meta.SessionID)
	}
	termErr := l.Terminator.Terminate(ctx, meta.SessionID, cred, relayErr == nil)
	if relayErr != nil {
		return relayErr
	}
	return termErr
}

package proxycore

import (
	"context"
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
}

func NewListener(fetcher *CredentialFetcher, terminator *Terminator) *Listener {
	return &Listener{Fetcher: fetcher, Terminator: terminator}
}

// Serve runs one session end-to-end. The caller supplies the Codec and the
// already-connected client/target streams; Serve owns the credential
// lifecycle and guarantees Purge runs exactly once, on every exit path.
func (l *Listener) Serve(ctx context.Context, meta SessionMetadata, codec Codec, client, target io.ReadWriter) error {
	cred, err := l.Fetcher.Fetch(ctx, meta.ScopeToken)
	if err != nil {
		_ = l.Terminator.EmitConnectFailure(ctx, meta.SessionID)
		return err
	}

	relayErr := codec.Relay(ctx, client, target, cred)
	termErr := l.Terminator.Terminate(ctx, meta.SessionID, cred, relayErr == nil)
	if relayErr != nil {
		return relayErr
	}
	return termErr
}

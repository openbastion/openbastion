package proxycore

// Serve and a session the Session Broker ends (ADR-0018): an open connection is cut and says
// why in the audit, a session that was ended never starts, nothing is fetched for it, and the
// credential is purged on every one of those paths.

import (
	"context"
	"errors"
	"io"
	"reflect"
	"sync"
	"testing"
	"time"
)

// holdCodec relays until its context ends, or until `release` is closed.
type holdCodec struct {
	started chan struct{}
	release chan struct{}
	called  bool
	cred    *Credential
}

func newHoldCodec() *holdCodec {
	return &holdCodec{started: make(chan struct{}), release: make(chan struct{})}
}

func (c *holdCodec) Relay(ctx context.Context, _, _ io.ReadWriter, cred *Credential) error {
	c.called, c.cred = true, cred
	close(c.started)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-c.release:
		return nil
	}
}

// hookVault runs onFetch while the credential is being fetched.
type hookVault struct {
	fakeVault
	onFetch func(ctx context.Context) error
}

func (v *hookVault) FetchCredential(ctx context.Context, scope, proxyID string) (string, []byte, error) {
	if v.onFetch != nil {
		if err := v.onFetch(ctx); err != nil {
			return "", nil, err
		}
	}
	return v.fakeVault.FetchCredential(ctx, scope, proxyID)
}

func revocable(vault VaultClient) (*Listener, *fakeAudit) {
	audit := &fakeAudit{}
	l := NewListener(NewCredentialFetcher(vault, "ssh-proxy-instance-1"), NewTerminator(audit))
	l.Recording = RecordingConfig{Policy: RecordingBestEffort} // these tests are not about recording
	return l, audit
}

func serve(l *Listener, id string, codec Codec) error {
	var client, target buf
	return l.Serve(context.Background(), SessionMetadata{SessionID: id, TargetHost: "10.0.0.5", ScopeToken: "scope"}, codec, &client, &target)
}

func TestServe_ARevocationCutsTheRelay_SaysSo_AndPurgesTheCredential(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := newHoldCodec()
	done := make(chan error, 1)
	go func() { done <- serve(l, "A", codec) }()
	<-codec.started

	rev := l.Live.Revoke("A", time.Now().Add(time.Hour))
	if rev.Cut() != 1 {
		t.Fatalf("the revocation signalled %d connections, want the one that is relaying", rev.Cut())
	}
	if left := rev.Wait(5 * time.Second); left != 0 {
		t.Fatalf("%d connections still open after the wait: the relay did not end", left)
	}
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if !codec.cred.Purged() {
		t.Fatal("the credential was not purged after the session was cut")
	}
	if want := []string{"session.revoked", "session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v: the cut says why, then the connection ends", audit.events, want)
	}
	if n := l.Live.OpenConnections("A"); n != 0 {
		t.Fatalf("%d connections still registered after Serve returned", n)
	}
}

func TestServe_ASessionThatWasEndedNeverStarts_AndNothingIsFetchedForIt(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, audit := revocable(vault)
	l.Live.Revoke("A", time.Now().Add(time.Hour))
	codec := &fakeCodec{}

	if err := serve(l, "A", codec); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if vault.calls != 0 {
		t.Fatalf("the Vault was asked for a credential %d times for a session that was ended: a single-use scope would be burnt for nothing", vault.calls)
	}
	if codec.relayCalledWith != nil {
		t.Fatal("the relay ran for a session that was ended")
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events %v for a session refused at the door, want none", audit.events)
	}
	if n := l.Live.OpenConnections("A"); n != 0 {
		t.Fatalf("%d connections registered for a refused session", n)
	}
}

func TestServe_ACutWhileTheCredentialIsBeingFetchedIsNotAFailedConnection(t *testing.T) {
	vault := &hookVault{fakeVault: fakeVault{material: []byte("ephemeral-secret")}}
	l, audit := revocable(vault)
	vault.onFetch = func(ctx context.Context) error {
		l.Live.Revoke("A", time.Now().Add(time.Hour))
		<-ctx.Done() // the fetch is interrupted by the cut, as an HTTP call would be
		return ctx.Err()
	}
	codec := &fakeCodec{}

	if err := serve(l, "A", codec); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if len(audit.events) != 0 {
		t.Fatalf("audit events %v, want none: a fetch cut short by a revocation is not a session.connect failure", audit.events)
	}
	if codec.relayCalledWith != nil {
		t.Fatal("the relay ran")
	}
}

func TestServe_ACutBetweenTheFetchAndTheRelayNeverContactsTheTarget_AndPurges(t *testing.T) {
	vault := &hookVault{fakeVault: fakeVault{material: []byte("ephemeral-secret")}}
	l, audit := revocable(vault)
	vault.onFetch = func(context.Context) error { // the fetch succeeds; the cut lands right after it
		l.Live.Revoke("A", time.Now().Add(time.Hour))
		return nil
	}
	codec := &fakeCodec{}

	if err := serve(l, "A", codec); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if codec.relayCalledWith != nil {
		t.Fatal("the relay ran after the session was cut: the target would have been logged in to")
	}
	if want := []string{"session.revoked", "session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v", audit.events, want)
	}
}

func TestServe_AListenerWithNoRegistryServesNothing(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	l, _ := revocable(vault)
	l.Live = nil
	codec := &fakeCodec{}

	if err := serve(l, "A", codec); !errors.Is(err, ErrNotRevocable) {
		t.Fatalf("Serve returned %v, want ErrNotRevocable: a connection nobody could cut is not started", err)
	}
	if vault.calls != 0 || codec.relayCalledWith != nil {
		t.Fatalf("something ran for a listener that could not cut it: vault calls %d", vault.calls)
	}
}

func TestServe_ARevocationOfAnotherSessionChangesNothing_AndNoCutIsReportedForAnOrdinaryEnd(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := newHoldCodec()
	done := make(chan error, 1)
	go func() { done <- serve(l, "A", codec) }()
	<-codec.started

	if cut := l.Live.Revoke("B", time.Now().Add(time.Hour)).Cut(); cut != 0 {
		t.Fatalf("revoking B cut %d connections of A", cut)
	}
	close(codec.release) // the operator logs out
	if err := <-done; err != nil {
		t.Fatalf("Serve returned %v, want a normal end", err)
	}
	if want := []string{"session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v: nothing was cut", audit.events, want)
	}
	if n := l.Live.OpenConnections("A"); n != 0 {
		t.Fatalf("%d connections registered after a normal end", n)
	}
}

func TestServe_ExpiryIsStillExpiry_NotARevocation(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := newHoldCodec()
	var client, target buf
	meta := SessionMetadata{SessionID: "A", TargetHost: "10.0.0.5", ScopeToken: "scope", ExpiresAt: time.Now().Add(50 * time.Millisecond)}

	if err := l.Serve(context.Background(), meta, codec, &client, &target); !errors.Is(err, ErrSessionExpired) {
		t.Fatalf("Serve returned %v, want ErrSessionExpired", err)
	}
	if want := []string{"session.expire", "session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v", audit.events, want)
	}
}

// flagAudit records each event with its success flag, and can hold an event back until it is
// released: an audit that is slow must not slow a revocation down.
type flagAudit struct {
	mu     sync.Mutex
	events []string
	gate   chan struct{} // when not nil, every event waits for it to be closed
}

func (f *flagAudit) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	if f.gate != nil {
		<-f.gate
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	flag := ":false"
	if success {
		flag = ":true"
	}
	f.events = append(f.events, action+flag)
	return nil
}

func (f *flagAudit) snapshot() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.events...)
}

func flagged(audit *flagAudit) *Listener {
	l := NewListener(NewCredentialFetcher(&fakeVault{material: []byte("ephemeral-secret")}, "ssh-proxy-instance-1"), NewTerminator(audit))
	l.Recording = RecordingConfig{Policy: RecordingBestEffort}
	return l
}

// A session that was cut ended as it was meant to: its termination is a success, on the
// record, whether the cut came during the relay or just before it.
func TestServe_ACutSessionsTerminationIsASuccessOnTheRecord(t *testing.T) {
	want := []string{"session.revoked:true", "session.terminate:true"}

	t.Run("during the relay", func(t *testing.T) {
		audit := &flagAudit{}
		l := flagged(audit)
		codec := newHoldCodec()
		done := make(chan error, 1)
		go func() { done <- serve(l, "A", codec) }()
		<-codec.started
		l.Live.Revoke("A", time.Now().Add(time.Hour)).Wait(5 * time.Second)
		if err := <-done; !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("Serve returned %v", err)
		}
		if got := audit.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("audit %v, want %v", got, want)
		}
	})

	t.Run("between the fetch and the relay", func(t *testing.T) {
		audit := &flagAudit{}
		l := flagged(audit)
		l.Fetcher = NewCredentialFetcher(&afterFetchRevoke{inner: &fakeVault{material: []byte("ephemeral-secret")}, live: l.Live}, "ssh-proxy-instance-1")
		if err := serve(l, "A", &fakeCodec{}); !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("Serve returned %v", err)
		}
		if got := audit.snapshot(); !reflect.DeepEqual(got, want) {
			t.Fatalf("audit %v, want %v", got, want)
		}
	})
}

// afterFetchRevoke revokes the session the instant its credential has been handed over.
type afterFetchRevoke struct {
	inner VaultClient
	live  *LiveSessions
}

func (v *afterFetchRevoke) FetchCredential(ctx context.Context, scope, proxyID string) (string, []byte, error) {
	kind, material, err := v.inner.FetchCredential(ctx, scope, proxyID)
	v.live.Revoke("A", time.Now().Add(time.Hour))
	return kind, material, err
}

// What a revocation waits for is the end of the connection to the target, not the end of the
// bookkeeping after it: an audit that is slow, or down, does not make the Broker believe the
// session is still open.
func TestServe_ARevocationDoesNotWaitForTheAuditAfterTheRelayEnded(t *testing.T) {
	audit := &flagAudit{gate: make(chan struct{})}
	l := flagged(audit)
	codec := newHoldCodec()
	done := make(chan error, 1)
	go func() { done <- serve(l, "A", codec) }()
	<-codec.started

	rev := l.Live.Revoke("A", time.Now().Add(time.Hour))
	if left := rev.Wait(2 * time.Second); left != 0 {
		t.Fatalf("%d connection(s) still open: the revocation was waiting for the audit, which is held back", left)
	}
	close(audit.gate)
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v", err)
	}
}

// The session's deadline is under its revocation: a session with a time limit — which is
// every real one — is cut like any other.
func TestServe_ARevocationCutsASessionThatHasATimeLimit(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := newHoldCodec()
	var client, target buf
	meta := SessionMetadata{SessionID: "A", TargetHost: "10.0.0.5", ScopeToken: "scope", ExpiresAt: time.Now().Add(time.Hour)}
	done := make(chan error, 1)
	go func() { done <- l.Serve(context.Background(), meta, codec, &client, &target) }()
	<-codec.started

	if left := l.Live.Revoke("A", time.Now().Add(2*time.Hour)).Wait(2 * time.Second); left != 0 {
		t.Fatalf("%d connection(s) still open: a session with a deadline was not cut", left)
	}
	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if want := []string{"session.revoked", "session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v", audit.events, want)
	}
}

// lateCodec ignores its context until released, as a relay stuck in a write would.
type lateCodec struct {
	started chan struct{}
	release chan struct{}
}

func (c *lateCodec) Relay(ctx context.Context, _, _ io.ReadWriter, _ *Credential) error {
	close(c.started)
	<-c.release
	return ctx.Err()
}

// A session that is cut after its time ran out, while the relay has not yet noticed either,
// is told as a cut: the Broker's order is what the audit says, not the clock.
func TestServe_ACutThatLandsAfterTheDeadlineIsStillACut(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := &lateCodec{started: make(chan struct{}), release: make(chan struct{})}
	var client, target buf
	meta := SessionMetadata{SessionID: "A", TargetHost: "10.0.0.5", ScopeToken: "scope", ExpiresAt: time.Now().Add(60 * time.Millisecond)}
	done := make(chan error, 1)
	go func() { done <- l.Serve(context.Background(), meta, codec, &client, &target) }()
	<-codec.started

	time.Sleep(150 * time.Millisecond) // the deadline has passed; the relay is still stuck
	l.Live.Revoke("A", time.Now().Add(time.Hour))
	close(codec.release)

	if err := <-done; !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v, want ErrSessionRevoked", err)
	}
	if want := []string{"session.revoked", "session.terminate"}; !reflect.DeepEqual(audit.events, want) {
		t.Fatalf("audit events %v, want %v: a session cut is not also said to have expired", audit.events, want)
	}
}

// A proxy that is shutting down stops its connections; that is not a revocation, and the audit
// does not say the Broker ended the session.
func TestServe_AStopOfTheCallerIsNotARevocation(t *testing.T) {
	l, audit := revocable(&fakeVault{material: []byte("ephemeral-secret")})
	codec := newHoldCodec()
	ctx, stop := context.WithCancel(context.Background())
	var client, target buf
	done := make(chan error, 1)
	go func() {
		done <- l.Serve(ctx, SessionMetadata{SessionID: "A", TargetHost: "10.0.0.5", ScopeToken: "scope"}, codec, &client, &target)
	}()
	<-codec.started
	stop()

	err := <-done
	if errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Serve returned %v for a proxy that stopped: nobody revoked this session", err)
	}
	for _, e := range audit.events {
		if e == "session.revoked" {
			t.Fatalf("audit events %v: a shutdown was recorded as a revocation", audit.events)
		}
	}
}

package proxycore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"testing"
)

type fakeCodec struct {
	relayCalledWith *Credential
}

func (f *fakeCodec) Relay(ctx context.Context, client, target io.ReadWriter, cred *Credential) error {
	f.relayCalledWith = cred
	_ = cred.Material() // simulate protocol use — must not panic pre-purge
	return nil
}

type failingCodec struct{}

func (failingCodec) Relay(ctx context.Context, client, target io.ReadWriter, cred *Credential) error {
	return errBoom
}

var errBoom = errBoomType{}

type errBoomType struct{}

func (errBoomType) Error() string { return "boom" }

type fakeAudit struct {
	events []string
}

func (f *fakeAudit) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	f.events = append(f.events, action)
	return nil
}

type buf struct{ bytes.Buffer }

func TestListener_Serve_PurgesCredentialAfterSuccessfulRelay(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	fetcher := NewCredentialFetcher(vault, "ssh-proxy-instance-1")
	audit := &fakeAudit{}
	terminator := NewTerminator(audit)
	listener := NewListener(fetcher, terminator)
	listener.Recording = RecordingConfig{Policy: RecordingBestEffort} // these tests are not about recording

	codec := &fakeCodec{}
	meta := SessionMetadata{SessionID: "session-xyz", TargetHost: "10.0.0.5", ScopeToken: "scope-abc"}

	var client, target buf
	if err := listener.Serve(context.Background(), meta, codec, &client, &target); err != nil {
		t.Fatalf("Serve: %v", err)
	}

	if codec.relayCalledWith == nil {
		t.Fatal("Codec.Relay was not invoked")
	}
	for _, b := range codec.relayCalledWith.material {
		if b != 0 {
			t.Fatalf("credential not purged after Serve returned: %v", codec.relayCalledWith.material)
		}
	}
	if len(audit.events) != 1 || audit.events[0] != "session.terminate" {
		t.Fatalf("expected exactly one session.terminate audit event, got %v", audit.events)
	}
}

func TestListener_Serve_PurgesEvenWhenCodecFails(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	fetcher := NewCredentialFetcher(vault, "ssh-proxy-instance-1")
	audit := &fakeAudit{}
	terminator := NewTerminator(audit)
	listener := NewListener(fetcher, terminator)
	listener.Recording = RecordingConfig{Policy: RecordingBestEffort} // these tests are not about recording

	meta := SessionMetadata{SessionID: "session-fail", TargetHost: "10.0.0.5", ScopeToken: "scope-abc"}
	var client, target buf

	err := listener.Serve(context.Background(), meta, failingCodec{}, &client, &target)
	if err == nil {
		t.Fatal("expected Serve to propagate the Codec error")
	}
	if len(audit.events) != 1 || audit.events[0] != "session.terminate" {
		t.Fatalf("expected a session.terminate audit event even on failure, got %v", audit.events)
	}
}

func TestListener_Serve_AuditsFailureWhenCredentialFetchFails(t *testing.T) {
	vault := &fakeVault{err: errBoom}
	fetcher := NewCredentialFetcher(vault, "ssh-proxy-instance-1")
	audit := &fakeAudit{}
	terminator := NewTerminator(audit)
	listener := NewListener(fetcher, terminator)
	listener.Recording = RecordingConfig{Policy: RecordingBestEffort} // these tests are not about recording

	meta := SessionMetadata{SessionID: "session-no-cred", TargetHost: "10.0.0.5", ScopeToken: "bad-token"}
	var client, target buf

	if err := listener.Serve(context.Background(), meta, &fakeCodec{}, &client, &target); err == nil {
		t.Fatal("expected Serve to fail when the credential fetch is rejected")
	}
	if len(audit.events) != 1 || audit.events[0] != "session.connect" {
		t.Fatalf("expected a session.connect failure audit event, got %v", audit.events)
	}
}

// -- record-or-refuse (ADR-0008) ------------------------------------------------

type fakeGate struct {
	err   error
	calls int
}

func (g *fakeGate) Ready(ctx context.Context) error { g.calls++; return g.err }

type nopBatchRecorder struct{}

func (nopBatchRecorder) RecordBatch(context.Context, []CommandEntry) error { return nil }

func requiredListener(vault *fakeVault, audit *fakeAudit, gate RecordingGate) *Listener {
	l := NewListener(NewCredentialFetcher(vault, "ssh-proxy-instance-1"), NewTerminator(audit))
	l.Recording = RecordingConfig{Policy: RecordingRequired, Strict: nopBatchRecorder{}, Gate: gate}
	return l
}

// The point of admitting BEFORE the fetch: a Vault scope token is single-use,
// so fetching one for a session that is then refused would burn it.
func TestListener_Serve_RefusesBeforeFetchingTheCredentialWhenRecordingIsNotReady(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &fakeAudit{}
	listener := requiredListener(vault, audit, &fakeGate{err: errors.New("connection refused")})
	codec := &fakeCodec{}

	var client, target buf
	err := listener.Serve(context.Background(), SessionMetadata{SessionID: "session-unrecordable", ScopeToken: "scope-abc"}, codec, &client, &target)

	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("expected ErrRecordingUnavailable, got %v", err)
	}
	if vault.calls != 0 {
		t.Fatalf("the credential was fetched (%d call) for a session that was refused", vault.calls)
	}
	if codec.relayCalledWith != nil {
		t.Fatal("the protocol relay ran for a session that was refused")
	}
	if len(audit.events) != 1 || audit.events[0] != "session.recording_unavailable" {
		t.Fatalf("expected exactly one session.recording_unavailable event, got %v", audit.events)
	}
}

func TestListener_Serve_RunsWhenRecordingIsReady(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &fakeAudit{}
	gate := &fakeGate{}
	listener := requiredListener(vault, audit, gate)

	var client, target buf
	if err := listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, &fakeCodec{}, &client, &target); err != nil {
		t.Fatalf("Serve: %v", err)
	}
	if gate.calls != 1 || vault.calls != 1 {
		t.Fatalf("expected one readiness probe and one credential fetch, got %d and %d", gate.calls, vault.calls)
	}
	if len(audit.events) != 1 || audit.events[0] != "session.terminate" {
		t.Fatalf("expected only session.terminate, got %v", audit.events)
	}
}

// A Listener nobody configured must refuse, not run unrecorded: the zero value
// of the policy is the strict one.
func TestListener_ZeroValueRecordingRefusesEverySession(t *testing.T) {
	vault := &fakeVault{material: []byte("x")}
	audit := &fakeAudit{}
	listener := NewListener(NewCredentialFetcher(vault, "p"), NewTerminator(audit))

	var client, target buf
	err := listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, &fakeCodec{}, &client, &target)
	if !errors.Is(err, ErrRecordingUnavailable) || vault.calls != 0 {
		t.Fatalf("an unconfigured Listener must refuse before the fetch: err=%v fetches=%d", err, vault.calls)
	}
}

// The recording stops mid-session: the relay reports it, the Listener audits
// it under its own action, and the credential is still purged.
func TestListener_Serve_AuditsASessionEndedByRecordingLoss(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &fakeAudit{}
	listener := requiredListener(vault, audit, &fakeGate{})

	lossCodec := &recordingLossCodec{}
	var client, target buf
	err := listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, lossCodec, &client, &target)

	if !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("Serve must surface the loss, got %v", err)
	}
	if len(audit.events) != 2 || audit.events[0] != "session.recording_lost" || audit.events[1] != "session.terminate" {
		t.Fatalf("expected [session.recording_lost session.terminate], got %v", audit.events)
	}
	for _, b := range lossCodec.cred.material {
		if b != 0 {
			t.Fatal("the credential was not purged after the recording was lost")
		}
	}
}

type recordingLossCodec struct{ cred *Credential }

func (c *recordingLossCodec) Relay(ctx context.Context, client, target io.ReadWriter, cred *Credential) error {
	c.cred = cred
	return fmt.Errorf("%w: command-recorder: status 503", ErrRecordingUnavailable)
}

// An ordinary relay failure is NOT a recording loss, and must not be
// reported as one.
func TestListener_Serve_DoesNotReportOrdinaryFailuresAsRecordingLoss(t *testing.T) {
	vault := &fakeVault{material: []byte("ephemeral-secret")}
	audit := &fakeAudit{}
	listener := requiredListener(vault, audit, &fakeGate{})

	var client, target buf
	_ = listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, failingCodec{}, &client, &target)
	for _, e := range audit.events {
		if e == "session.recording_lost" {
			t.Fatalf("an ordinary failure was reported as a recording loss: %v", audit.events)
		}
	}
}

// The target did not present its pinned host key (ADR-0039): the Listener audits it under its
// own action — what an interposition looks like — and the session does not end cleanly.
// Counter-proof: an ordinary failure is not reported as one.
func TestListener_Serve_AuditsAHostKeyMismatch(t *testing.T) {
	audit := &fakeAudit{}
	listener := requiredListener(&fakeVault{material: []byte("x")}, audit, &fakeGate{})
	var client, target buf
	err := listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, hostKeyCodec{}, &client, &target)
	if !errors.Is(err, ErrHostKeyMismatch) {
		t.Fatalf("Serve must surface the mismatch, got %v", err)
	}
	if len(audit.events) != 2 || audit.events[0] != "session.host_key_mismatch" || audit.events[1] != "session.terminate" {
		t.Fatalf("expected [session.host_key_mismatch session.terminate], got %v", audit.events)
	}

	audit = &fakeAudit{}
	listener = requiredListener(&fakeVault{material: []byte("x")}, audit, &fakeGate{})
	_ = listener.Serve(context.Background(), SessionMetadata{SessionID: "s", ScopeToken: "t"}, failingCodec{}, &client, &target)
	for _, e := range audit.events {
		if e == "session.host_key_mismatch" {
			t.Fatalf("an ordinary failure was reported as a host key mismatch: %v", audit.events)
		}
	}
}

type hostKeyCodec struct{}

func (hostKeyCodec) Relay(ctx context.Context, client, target io.ReadWriter, cred *Credential) error {
	return fmt.Errorf("target ssh handshake: %w: 10.0.0.5:22 presented SHA256:x, pinned SHA256:y", ErrHostKeyMismatch)
}

func TestListener_Admit_CanBeCalledAheadOfServe(t *testing.T) {
	audit := &fakeAudit{}
	listener := requiredListener(&fakeVault{}, audit, &fakeGate{err: errors.New("down")})
	if err := listener.Admit(context.Background(), "s"); !errors.Is(err, ErrRecordingUnavailable) {
		t.Fatalf("Admit must refuse, got %v", err)
	}
	if len(audit.events) != 1 || audit.events[0] != "session.recording_unavailable" {
		t.Fatalf("the refusal must be audited, got %v", audit.events)
	}
}

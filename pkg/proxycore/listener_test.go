package proxycore

import (
	"bytes"
	"context"
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

	meta := SessionMetadata{SessionID: "session-no-cred", TargetHost: "10.0.0.5", ScopeToken: "bad-token"}
	var client, target buf

	if err := listener.Serve(context.Background(), meta, &fakeCodec{}, &client, &target); err == nil {
		t.Fatal("expected Serve to fail when the credential fetch is rejected")
	}
	if len(audit.events) != 1 || audit.events[0] != "session.connect" {
		t.Fatalf("expected a session.connect failure audit event, got %v", audit.events)
	}
}

package sshcodec_test

import (
	"context"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/sshcodec"
)

type secretBatchRecorder struct {
	mu            sync.Mutex
	entries       []proxycore.CommandEntry
	markerStarted chan struct{}
	releaseMarker chan struct{}
}

func (r *secretBatchRecorder) RecordBatch(_ context.Context, entries []proxycore.CommandEntry) error {
	for _, entry := range entries {
		if strings.HasPrefix(entry.Command, "[vault secret ") && r.markerStarted != nil {
			r.markerStarted <- struct{}{}
			<-r.releaseMarker
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, entries...)
	return nil
}

func (r *secretBatchRecorder) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.entries))
	for _, entry := range r.entries {
		out = append(out, entry.Command)
	}
	return out
}

type secretAudit struct {
	mu     sync.Mutex
	events []proxycore.SecretInputEvidence
}

func (a *secretAudit) AuditSecretInput(_ context.Context, evidence proxycore.SecretInputEvidence) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, evidence)
	return nil
}

func (a *secretAudit) AuditSecretInputResult(context.Context, proxycore.SecretInputEvidence, bool) error {
	return nil
}

func TestSSHCodec_InjectsSecretOutsideOperatorRecording(t *testing.T) {
	const password = "target-real-secret-42"
	const scope = "scope-secret-injection"
	const sessionID = "session-secret-injection"

	var targetMu sync.Mutex
	var targetLines []string
	targetAddr := startObservedFakeTargetSSHServer(t, password, func(line string) {
		targetMu.Lock()
		defer targetMu.Unlock()
		targetLines = append(targetLines, line)
	})

	credential, err := proxycore.NewCredentialFetcher(&fakeVault{
		expectedScopeToken: scope, secret: password,
	}, "ssh-proxy").Fetch(context.Background(), scope)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(credential.Purge)

	target, err := net.DialTimeout("tcp", targetAddr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()

	proxySide, operatorSide := net.Pipe()
	defer proxySide.Close()
	defer operatorSide.Close()

	recorder := &secretBatchRecorder{
		markerStarted: make(chan struct{}, 1),
		releaseMarker: make(chan struct{}),
	}
	tap := proxycore.NewRequiredRecordingTap(recorder, sessionID)
	audit := &secretAudit{}
	typerReady := make(chan proxycore.SecretTyper, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	relayDone := make(chan error, 1)
	codec := &sshcodec.Codec{
		TargetUser: "root", DialTimeout: 5 * time.Second,
		Recorder: tap, OutputObserver: tap.Output(), Events: tap,
		SessionID: sessionID, SecretInputRecorder: tap,
		SecretTyperReady: func(_ context.Context, gotSessionID, protocol, targetHost, targetUser string, typer proxycore.SecretTyper, evidence proxycore.SecretInputRecorder) func() {
			if gotSessionID != sessionID {
				t.Errorf("registered session = %q", gotSessionID)
			}
			if evidence != tap {
				t.Error("secret injection did not receive the session recording tap")
			}
			typerReady <- typer
			return nil
		},
	}
	go func() { relayDone <- codec.Relay(ctx, proxySide, target, credential) }()
	go func() { _, _ = io.Copy(io.Discard, operatorSide) }()

	var typer proxycore.SecretTyper
	select {
	case typer = <-typerReady:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH codec did not register its live secret typer")
	}
	if _, err := operatorSide.Write([]byte("sudo -s\r\n")); err != nil {
		t.Fatal(err)
	}

	// The fake target emits the normal sudo prompt before it accepts the next line.
	time.Sleep(50 * time.Millisecond)
	secret := []byte("hunter2")
	injectionDone := make(chan error, 1)
	go func() {
		injectionDone <- proxycore.InjectSecret(ctx, sessionID, "ssh", proxycore.SecretInputVault,
			"root-prod", secret, audit, tap, typer)
	}()
	select {
	case <-recorder.markerStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("secret reference was not being durably recorded")
	}
	// An ordinary command arrives while the secret evidence is being committed.
	// It must wait behind the same input transaction, then follow the secret.
	if _, err := operatorSide.Write([]byte("id\r\n")); err != nil {
		t.Fatal(err)
	}
	close(recorder.releaseMarker)
	if err := <-injectionDone; err != nil {
		t.Fatalf("InjectSecret: %v", err)
	}
	for _, b := range secret {
		if b != 0 {
			t.Fatal("secret buffer was not purged")
		}
	}

	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		targetMu.Lock()
		found := false
		for _, line := range targetLines {
			if line == "hunter2" {
				found = true
			}
		}
		targetMu.Unlock()
		if found {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	targetMu.Lock()
	gotTargetLines := append([]string(nil), targetLines...)
	targetMu.Unlock()
	wantTargetLines := []string{"sudo -s", "hunter2", "id"}
	if len(gotTargetLines) != len(wantTargetLines) {
		t.Fatalf("target input order = %q, want %q", gotTargetLines, wantTargetLines)
	}
	for i := range wantTargetLines {
		if gotTargetLines[i] != wantTargetLines[i] {
			t.Fatalf("target input order = %q, want %q", gotTargetLines, wantTargetLines)
		}
	}

	// The explicit injection consumes the password-prompt state. The next
	// ordinary command remains visible in the recording, not falsely redacted.
	deadline = time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(recorder.commands()) >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	commands := recorder.commands()
	want := []string{"sudo -s", "[vault secret root-prod injection requested via ssh]", "id"}
	if len(commands) != len(want) {
		t.Fatalf("recorded commands = %q", commands)
	}
	for i := range want {
		if commands[i] != want[i] {
			t.Fatalf("recorded commands = %q", commands)
		}
	}
	for _, command := range commands {
		if strings.Contains(command, "hunter2") {
			t.Fatalf("secret leaked into recording: %q", command)
		}
	}

	audit.mu.Lock()
	if len(audit.events) != 1 || audit.events[0].Source != proxycore.SecretInputVault || audit.events[0].AccountID != "root-prod" {
		t.Fatalf("audit evidence = %+v", audit.events)
	}
	audit.mu.Unlock()

	cancel()
	select {
	case <-relayDone:
	case <-time.After(5 * time.Second):
		t.Fatal("SSH relay did not stop after cancellation")
	}
}

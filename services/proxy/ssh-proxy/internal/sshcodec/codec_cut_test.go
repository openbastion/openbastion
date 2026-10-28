package sshcodec_test

// A session that is cut (ADR-0018) ends the connection to the target at once, whatever the
// handshake is doing: ssh.NewClientConn has no context of its own, so without this a target
// that answers slowly — or never — would keep a revoked session's login going.

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/sshcodec"
)

func TestRelay_ACutDuringTheTargetHandshakeEndsItAtOnce_AndClosesTheTargetConnection(t *testing.T) {
	cred, err := proxycore.NewCredentialFetcher(&fakeVault{expectedScopeToken: "scope", secret: "pw"}, "ssh-proxy").Fetch(context.Background(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	proxySide, targetSide := net.Pipe() // the target reads our greeting and never answers
	defer targetSide.Close()
	go func() {
		buf := make([]byte, 4096)
		for {
			if _, err := targetSide.Read(buf); err != nil {
				return
			}
		}
	}()

	ctx, cut := context.WithCancelCause(context.Background())
	done := make(chan error, 1)
	// DialTimeout is zero: nothing but the cut can end this handshake.
	go func() {
		var client bytes.Buffer
		done <- (&sshcodec.Codec{TargetUser: "root"}).Relay(ctx, &client, proxySide, cred)
	}()

	time.Sleep(150 * time.Millisecond) // the handshake is under way, waiting for the target
	select {
	case err := <-done:
		t.Fatalf("Relay returned before anything cut it: %v", err)
	default:
	}
	cut(proxycore.ErrSessionRevoked)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a handshake that was cut succeeded")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the handshake went on after the session was cut")
	}
	// The connection to the target is closed, not just abandoned.
	if _, err := proxySide.Write([]byte("x")); err == nil {
		t.Fatalf("the connection to the target is still open after the cut: write returned %v", err)
	}
}

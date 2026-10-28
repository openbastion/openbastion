// Package sshcodec implements proxycore.Codec for SSH — the first real
// protocol implementation in OpenBastion, using the actual
// golang.org/x/crypto/ssh package (see go.mod and /NOTES_SANDBOX.md for
// how it's fetched in this build sandbox).
//
// By the time Relay is called, the server-side SSH handshake with the
// client has ALREADY happened — see ../interfaces/server.go — because
// resolving which pending session an incoming TCP connection belongs to
// requires completing that handshake (the connection ticket is presented
// as the SSH password). client is therefore an already-open ssh.Channel
// (which satisfies io.ReadWriter), not a raw net.Conn. target, by
// contrast, is a freshly dialed net.Conn to the privileged account's
// host — Relay performs the SSH CLIENT handshake to it itself, using the
// credential that pkg/proxycore.Listener fetched immediately before
// calling Relay (ADR-0003: this is the only place in ssh-proxy that ever
// sees the credential's plaintext).
package sshcodec

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// Codec relays one interactive SSH shell session. A new Codec is
// constructed per connection by the connection handler, once the
// connection ticket has resolved which target/account it belongs to.
type Codec struct {
	// TargetUser is the account username to authenticate as on the
	// target — privileged_accounts.username (OpenBastion_06_Modele_Donnees.md
	// §3) and proto/proxy/v1/proxy_control.proto's
	// EstablishSessionRequest.target_user, both added after this codec
	// first needed the value and had nowhere formal to carry it; see
	// NOTES_SANDBOX.md. The connection handler threads it through from
	// EstablishSessionRequest in ../interfaces/http.go.
	TargetUser string

	// Recorder receives everything the client types, for command capture
	// (doc 00's Command Recorder). May be nil, in which case nothing is
	// captured — the relay itself never depends on it.
	Recorder io.Writer

	// OutputObserver receives everything the target sends back, so the
	// Recorder side can tell when the target is asking for a secret (sudo,
	// su, ssh prompts) and avoid storing what the operator types next —
	// proxycore.RecordingTap.Output is the implementation. May be nil. It
	// only ever observes: what is relayed to the client is unchanged, and
	// it must never fail or block.
	OutputObserver io.Writer

	// DialTimeout bounds the SSH handshake to the target. Zero means
	// ssh.ClientConfig's own default (no timeout), which is not what we
	// want in production — cmd/ssh-proxy sets this explicitly.
	DialTimeout time.Duration
}

// Relay implements proxycore.Codec.
func (c *Codec) Relay(ctx context.Context, client, target io.ReadWriter, credential *proxycore.Credential) error {
	targetConn, ok := target.(net.Conn)
	if !ok {
		return fmt.Errorf("sshcodec: target must be a net.Conn, got %T", target)
	}

	// A session that is cut (revoked, ADR-0018) or that runs out of time closes its
	// connection to the target at once — in the middle of the handshake too, which
	// has no context of its own — instead of finishing a login nobody may use.
	stopCut := context.AfterFunc(ctx, func() { _ = targetConn.Close() })
	defer stopCut()

	clientConfig := &ssh.ClientConfig{
		User:            c.TargetUser,
		Auth:            []ssh.AuthMethod{ssh.Password(string(credential.Material()))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // MVP: no host key pinning yet — see NOTES_SANDBOX.md
		Timeout:         c.DialTimeout,
	}

	targetSSHConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetConn.RemoteAddr().String(), clientConfig)
	if err != nil {
		return fmt.Errorf("target ssh handshake as %q: %w", c.TargetUser, err)
	}
	targetClient := ssh.NewClient(targetSSHConn, chans, reqs)
	defer targetClient.Close()

	session, err := targetClient.NewSession()
	if err != nil {
		return fmt.Errorf("target session: %w", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		return fmt.Errorf("target pty request: %w", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("target stdin pipe: %w", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return fmt.Errorf("target stdout pipe: %w", err)
	}
	if err := session.Shell(); err != nil {
		return fmt.Errorf("target shell: %w", err)
	}

	var clientReader io.Reader = client
	if c.Recorder != nil {
		clientReader = io.TeeReader(client, c.Recorder)
	}

	var targetReader io.Reader = stdout
	if c.OutputObserver != nil {
		targetReader = io.TeeReader(stdout, c.OutputObserver)
	}

	done := make(chan error, 2)
	go func() {
		_, err := io.Copy(stdin, clientReader)
		done <- err
	}()
	go func() {
		_, err := io.Copy(client, targetReader)
		done <- err
	}()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case err := <-done:
		if err != nil && err != io.EOF {
			return err
		}
		return nil
	}
}

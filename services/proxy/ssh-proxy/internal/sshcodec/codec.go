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
	"bytes"
	"context"
	"errors"
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

	// TargetHost is the address the session names (from the Broker): it must be the one the
	// Vault gave the secret for (ADR-0039). Empty: not compared.
	TargetHost string

	// Mode is what the client asked for on its session channel (ADR-0038): an interactive
	// shell (the zero value), the SFTP subsystem, or a legacy scp sink or source (SCP).
	Mode Mode
	SCP  SCPCommand
	// Events records the transfers of an SFTP or SCP session before they are relayed;
	// required for those modes.
	Events EventRecorder
}

// Mode is the kind of session relayed.
type Mode int

const (
	ModeShell Mode = iota
	ModeSFTP
	ModeSCP
)

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

	// The target must present the host key the Vault pinned for this secret (ADR-0039), and
	// be the target the Vault gave it for: otherwise not one byte of the secret is sent.
	pinned, err := pinnedHostKey(credential)
	if err != nil {
		return err
	}
	if credential.TargetHost != "" && c.TargetHost != "" && credential.TargetHost != c.TargetHost {
		return fmt.Errorf("%w: the session names %s, the Vault gave the secret for %s", ErrHostKeyMismatch, c.TargetHost, credential.TargetHost)
	}
	clientConfig := &ssh.ClientConfig{
		User:            c.TargetUser,
		Auth:            []ssh.AuthMethod{ssh.Password(string(credential.Material()))},
		HostKeyCallback: checkHostKey(pinned),
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

	if c.Mode == ModeSFTP || c.Mode == ModeSCP {
		return c.relayTransfer(ctx, client, session)
	}

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

	// The operator's input ending (`ssh … < /dev/null`, `echo cmd | ssh …`) is not a hang-up:
	// the target is told (its input closes) and what it still answers is relayed, until it
	// ends the shell — as sshd does. An error on that side — a command that could not be
	// recorded above all (ADR-0008) — still ends the session at once.
	fromClient := make(chan error, 1)
	toClient := make(chan error, 1)
	go func() {
		_, err := io.Copy(stdin, clientReader)
		fromClient <- err
	}()
	go func() {
		_, err := io.Copy(client, targetReader)
		toClient <- err
	}()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-fromClient:
			if err != nil && err != io.EOF {
				return err
			}
			_ = stdin.Close()
			fromClient = nil // nothing more from the operator; wait for the target
		case err := <-toClient:
			if err != nil && err != io.EOF {
				return err
			}
			return nil
		}
	}
}

// relayTransfer relays an SFTP or SCP session (ADR-0038), each transfer recorded before it is
// relayed. The target's exit status goes back to the client, as an SSH server would send it.
func (c *Codec) relayTransfer(ctx context.Context, client io.ReadWriter, session *ssh.Session) error {
	if c.Events == nil {
		return fmt.Errorf("sshcodec: a transfer session needs an event recorder")
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		return err
	}
	var up, down func() error
	switch c.Mode {
	case ModeSFTP:
		if err := session.RequestSubsystem("sftp"); err != nil {
			return fmt.Errorf("target sftp subsystem: %w", err)
		}
		w := newSFTPWatch(c.Events)
		up = func() error { return w.clientToTarget(ctx, client, stdin) }
		down = func() error { return w.targetToClient(stdout, client) }
	case ModeSCP:
		if err := c.Events.RecordEvent(ctx, fmt.Sprintf("scp %s %s", map[bool]string{true: "upload to", false: "download from"}[c.SCP.Upload], q(c.SCP.Path))); err != nil {
			return err
		}
		if err := session.Start(c.SCP.Line); err != nil {
			return fmt.Errorf("target scp: %w", err)
		}
		if c.SCP.Upload {
			up = func() error { return scpStream(ctx, c.Events, c.SCP, client, stdin) }
			down = func() error { _, err := io.Copy(client, stdout); return err }
		} else {
			up = func() error { _, err := io.Copy(stdin, client); return err }
			down = func() error { return scpStream(ctx, c.Events, c.SCP, stdout, client) }
		}
	}
	upDone := make(chan error, 1)
	go func() {
		err := up()
		_ = stdin.Close() // the client is done: the target sees the end of its input
		upDone <- err
	}()
	downErr := down()
	exit := 0
	if c.Mode == ModeSCP {
		if err := session.Wait(); err != nil {
			exit = 1
			var ee *ssh.ExitError
			if errors.As(err, &ee) {
				exit = ee.ExitStatus()
			}
		}
	}
	// As an sshd does: the exit status, then the channel closed — which also ends the copy
	// of whatever the client still sends.
	if ch, ok := client.(ssh.Channel); ok {
		_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ Status uint32 }{uint32(exit)}))
		_ = ch.CloseWrite()
		_ = ch.Close()
	}
	select {
	case err := <-upDone:
		if err != nil && err != io.EOF {
			return err
		}
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(5 * time.Second):
	}
	if downErr != nil && downErr != io.EOF {
		return downErr
	}
	return nil
}

// ErrHostKeyMismatch is proxycore.ErrHostKeyMismatch (ADR-0039): nothing of the secret was sent.
var ErrHostKeyMismatch = proxycore.ErrHostKeyMismatch

func pinnedHostKey(credential *proxycore.Credential) (ssh.PublicKey, error) {
	if credential.HostKey == "" {
		return nil, fmt.Errorf("%w: the Vault gave no pinned host key", ErrHostKeyMismatch)
	}
	k, _, _, _, err := ssh.ParseAuthorizedKey([]byte(credential.HostKey))
	if err != nil {
		return nil, fmt.Errorf("%w: the pinned host key does not read: %v", ErrHostKeyMismatch, err)
	}
	return k, nil
}

// checkHostKey accepts exactly the pinned key, and says what was seen otherwise.
func checkHostKey(pinned ssh.PublicKey) ssh.HostKeyCallback {
	return func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if bytes.Equal(key.Marshal(), pinned.Marshal()) {
			return nil
		}
		return fmt.Errorf("%w: %s presented %s, pinned %s", ErrHostKeyMismatch, hostname, ssh.FingerprintSHA256(key), ssh.FingerprintSHA256(pinned))
	}
}

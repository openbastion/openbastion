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
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/hostkey"
	"github.com/openbastion/openbastion/pkg/proxycore"
)

// Codec relays one interactive SSH shell session. A new Codec is
// constructed per connection by the connection handler, once the
// connection ticket has resolved which target/account it belongs to.
type Codec struct {
	// TargetUser is the account username to authenticate as on the
	// target — privileged_accounts.username (docs/architecture/data-architecture.md
	// §3) and proto/proxy/v1/proxy_control.proto's
	// EstablishSessionRequest.target_user, both added after this codec
	// first needed the value and had nowhere formal to carry it; see
	// NOTES_SANDBOX.md. The connection handler threads it through from
	// EstablishSessionRequest in ../interfaces/http.go.
	TargetUser string

	// Recorder receives everything the client types, for command capture
	// (docs/architecture/system-overview.md's Command Recorder). May be nil, in which case nothing is
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

	// SessionID and SecretTyperReady expose the active target input stream to the
	// proxy's authenticated session-control path (ADR-0097). The callback is
	// invoked only after the target shell is ready and must return a cleanup
	// function that removes the live session registration.
	SessionID           string
	SecretInputRecorder proxycore.SecretInputRecorder
	SecretTyperReady    func(ctx context.Context, sessionID, protocol, targetHost, targetUser string, typer proxycore.SecretTyper, recorder proxycore.SecretInputRecorder) func()
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
	if credential == nil {
		return fmt.Errorf("sshcodec: missing credential")
	}
	defer credential.Purge()
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
	trust, err := pinnedTrust(credential)
	if err != nil {
		return err
	}
	if credential.TargetHost != "" && c.TargetHost != "" && credential.TargetHost != c.TargetHost {
		return fmt.Errorf("%w: the session names %s, the Vault gave the secret for %s", ErrHostKeyMismatch, c.TargetHost, credential.TargetHost)
	}
	// x/crypto/ssh accepts passwords as strings. Build that immutable copy only
	// when the authentication callback runs, then drop the callback and purge the
	// byte buffer immediately after the target handshake (ADR-0003).
	passwordMaterial := credential.Material()
	clientConfig := &ssh.ClientConfig{
		User: c.TargetUser,
		Auth: []ssh.AuthMethod{ssh.PasswordCallback(func() (string, error) {
			return string(passwordMaterial), nil
		})},
		Timeout: c.DialTimeout,
	}
	// The pinned key, or a certificate of the pinned authority for its name (ADR-0048); every
	// refusal is an ErrHostKeyMismatch, and nothing is sent.
	trust.Configure(clientConfig, nil)
	verify := clientConfig.HostKeyCallback
	clientConfig.HostKeyCallback = func(hostname string, remote net.Addr, key ssh.PublicKey) error {
		if err := verify(hostname, remote, key); err != nil {
			return fmt.Errorf("%w: %v", ErrHostKeyMismatch, err)
		}
		return nil
	}

	targetSSHConn, chans, reqs, err := ssh.NewClientConn(targetConn, targetConn.RemoteAddr().String(), clientConfig)
	credential.Purge()
	passwordMaterial = nil
	clientConfig.Auth = nil
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

	// Both ordinary operator input and privileged secret injection share one
	// serialized writer. The secret path writes directly to target stdin and
	// bypasses Recorder; it is never copied into the client-to-target tee.
	input := &serializedSSHInput{writer: stdin}
	if c.SecretTyperReady != nil {
		cleanup := c.SecretTyperReady(ctx, c.SessionID, "ssh", c.TargetHost, c.TargetUser, input, c.SecretInputRecorder)
		if cleanup != nil {
			defer cleanup()
		}
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
		_, err := relayOperatorInput(input, client, c.Recorder)
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

func pinnedTrust(credential *proxycore.Credential) (hostkey.Trust, error) {
	if credential.HostKey == "" {
		return hostkey.Trust{}, fmt.Errorf("%w: the Vault gave no pinned host key", ErrHostKeyMismatch)
	}
	t, err := hostkey.Parse(credential.HostKey)
	if err != nil {
		return hostkey.Trust{}, fmt.Errorf("%w: the pinned host key does not read: %v", ErrHostKeyMismatch, err)
	}
	return t, nil
}

// serializedSSHInput ensures secret injection cannot interleave bytes with
// ordinary operator input. Ordinary input still arrives through the recorder
// tee; TypeSecret writes directly to the target and therefore bypasses capture.
type serializedSSHInput struct {
	mu     sync.Mutex
	writer io.Writer
}

func (w *serializedSSHInput) writeOperatorInput(p []byte, recorder io.Writer) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if recorder != nil {
		n, err := recorder.Write(p)
		if err != nil {
			return 0, err
		}
		if n != len(p) {
			return 0, io.ErrShortWrite
		}
	}
	return w.writer.Write(p)
}

func relayOperatorInput(input *serializedSSHInput, source io.Reader, recorder io.Writer) (int64, error) {
	buffer := make([]byte, 32*1024)
	var total int64
	for {
		n, readErr := source.Read(buffer)
		if n > 0 {
			written, writeErr := input.writeOperatorInput(buffer[:n], recorder)
			total += int64(written)
			if writeErr != nil {
				return total, writeErr
			}
		}
		if readErr != nil {
			return total, readErr
		}
	}
}

// TypeSecret types one line into the active SSH PTY. The caller owns and purges
// the supplied buffer; this method neither copies nor retains it.
func (w *serializedSSHInput) WithExclusiveInput(ctx context.Context, operation func() error) error {
	if w == nil || operation == nil {
		return proxycore.ErrSecretInjectionInvalid
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return operation()
}

func (w *serializedSSHInput) TypeSecret(ctx context.Context, secret []byte) error {
	if w == nil || w.writer == nil || ctx == nil || ctx.Err() != nil || len(secret) == 0 || !utf8.Valid(secret) {
		return proxycore.ErrSecretInjectionInvalid
	}
	for _, r := range string(secret) {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f {
			return proxycore.ErrSecretInjectionInvalid
		}
	}
	if _, err := w.writer.Write(secret); err != nil {
		return err
	}
	_, err := io.WriteString(w.writer, "\r")
	return err
}

var (
	_ proxycore.SecretTyper            = (*serializedSSHInput)(nil)
	_ proxycore.SecretInputTransaction = (*serializedSSHInput)(nil)
)

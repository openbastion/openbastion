// Package interfaces holds the SSH Proxy's two inbound surfaces: the real
// SSH listener (this file) that terminates client connections, and the
// HTTP implementation of ProxyControl (http.go) that the Session Broker
// calls to authorize a pending session.
package interfaces

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/sshcodec"
)

// SSHServer accepts client connections and drives each one through
// pkg/proxycore.Listener. Only the connection ticket — presented as the
// SSH password — determines which pending session an incoming connection
// belongs to (ADR-0003: nothing here is a secret; the actual credential
// is fetched later, inside sshcodec.Codec.Relay, by pkg/proxycore).
type SSHServer struct {
	HostSigner  ssh.Signer
	Pending     *infrastructure.PendingSessions
	Listener    *proxycore.Listener // owns credential fetch + purge + audit (docs/architecture/components.md)
	DialTimeout time.Duration

	// SecretTyperReady registers the active SSH target input stream for the
	// authenticated session-control path (ADR-0097). It is deliberately a
	// callback: this listener does not expose an unauthenticated injection API.
	SecretTyperReady func(ctx context.Context, sessionID, protocol, targetHost, targetUser string, typer proxycore.SecretTyper, recorder proxycore.SecretInputRecorder) func()
}

// recordingRefusedMessage is what the operator reads when the recording policy
// ends or refuses their session. It is deliberately generic — no recorder
// address, no error text — and it says the one thing that matters: nothing
// unrecorded was sent to the target.
const recordingRefusedMessage = "\r\nopenbastion: session ended because recording is unavailable. " +
	"No command that could not be recorded was sent to the target.\r\n"

// sessionExpiredMessage is what the operator reads when the proxy cuts the
// session at the end of its allotted time.
const sessionExpiredMessage = "\r\nopenbastion: session ended because its time limit was reached.\r\n"

// sessionRevokedMessage is what the operator reads when the session is ended while
// they are connected (ADR-0018). It does not say who ended it.
const sessionRevokedMessage = "\r\nopenbastion: session ended because it was terminated.\r\n"

// hostKeyMismatchMessage is what the operator reads when the target is not the one pinned
// (ADR-0039): the secret was not sent. The fingerprints are in the proxy's log and the audit.
const hostKeyMismatchMessage = "\r\nopenbastion: refused: the target did not present its pinned host key; nothing was sent to it. Report this to an administrator.\r\n"

// Serve accepts connections on ln until it errors or ctx is done.
func (s *SSHServer) Serve(ctx context.Context, ln net.Listener) error {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return nil
			default:
				return err
			}
		}
		go s.handleConnection(ctx, conn)
	}
}

func (s *SSHServer) handleConnection(ctx context.Context, conn net.Conn) {
	defer conn.Close()

	var resolved *infrastructure.PendingSession
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			ps, err := s.Pending.Consume(string(password))
			if err != nil {
				return nil, err
			}
			resolved = ps
			return &ssh.Permissions{}, nil
		},
	}
	config.AddHostKey(s.HostSigner)

	sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		log.Printf("ssh-proxy: client handshake failed: %v", err)
		return
	}
	defer sshConn.Close()
	go ssh.DiscardRequests(reqs)

	clientChannel, cleanup, shellRequested, starts, err := acceptSessionChannel(chans)
	if err != nil {
		log.Printf("ssh-proxy: %v", err)
		return
	}
	defer cleanup()
	// Nothing is dialed, admitted or fetched before the client says what it runs.
	var started sessionStart
	select {
	case started = <-starts:
	case <-time.After(30 * time.Second):
		log.Printf("ssh-proxy: session %s: the client asked for no shell, sftp or scp in 30 s", resolved.SessionID)
		return
	case <-ctx.Done():
		return
	}

	targetAddr := resolved.TargetHost
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		tell(clientChannel, shellRequested, fmt.Sprintf("openbastion: cannot reach target %s: %v\r\n", targetAddr, err))
		return
	}
	defer targetConn.Close()

	// The recording policy (ADR-0008) lives on the Listener, which owns the
	// session pipeline. Admission comes before the tap is built, because which
	// tap records this session depends on how it was admitted: an acknowledging
	// tap when the recorder is ready, a non-blocking one when a break-glass waiver
	// (ADR-0009) stands in for it. The decision is handed on to Serve, which would
	// otherwise ask again — and, for a waiver, audit it twice.
	admission, err := s.Listener.AdmitSession(ctx, resolved.SessionID, resolved.BreakGlass)
	if err != nil {
		log.Printf("ssh-proxy: session %s refused: %v", resolved.SessionID, err)
		tell(clientChannel, shellRequested, recordingRefusedMessage)
		return
	}
	if admission.Waived() {
		log.Printf("ssh-proxy: session %s runs under a BREAK-GLASS waiver: the Command Recorder is not ready, commands are recorded best-effort", resolved.SessionID)
	}
	recordingTap, err := s.Listener.Recording.NewTapFor(admission)
	if err != nil {
		log.Printf("ssh-proxy: session %s refused: %v", resolved.SessionID, err)
		tell(clientChannel, shellRequested, recordingRefusedMessage)
		return
	}

	meta := proxycore.SessionMetadata{
		SessionID:  resolved.SessionID,
		TargetHost: resolved.TargetHost,
		ScopeToken: resolved.ScopeToken,
		ExpiresAt:  resolved.ExpiresAt,
		BreakGlass: resolved.BreakGlass,
		Admission:  admission,
	}
	codec := &sshcodec.Codec{
		TargetUser:          resolved.TargetUser,
		SessionID:           resolved.SessionID,
		SecretInputRecorder: recordingTap,
		SecretTyperReady:    s.SecretTyperReady,
		Recorder:            recordingTap,
		// The target's output feeds the tap's secret-prompt detection, so a
		// sudo password typed next is recorded as redacted, not in the clear.
		OutputObserver: recordingTap.Output(),
		DialTimeout:    s.DialTimeout,
		// The address the session names: it must be the Vault's for this secret (ADR-0039).
		TargetHost: resolved.TargetHost,
		// SFTP and SCP: each transfer recorded before it is relayed (ADR-0038).
		Mode:   started.mode,
		SCP:    started.scp,
		Events: recordingTap,
	}

	if err := s.Listener.Serve(ctx, meta, codec, clientChannel, targetConn); err != nil {
		log.Printf("ssh-proxy: session %s: %v", meta.SessionID, err)
		switch {
		case errors.Is(err, proxycore.ErrRecordingUnavailable):
			tell(clientChannel, shellRequested, recordingRefusedMessage)
		case errors.Is(err, proxycore.ErrSessionExpired):
			tell(clientChannel, shellRequested, sessionExpiredMessage)
		case errors.Is(err, proxycore.ErrSessionRevoked):
			tell(clientChannel, shellRequested, sessionRevokedMessage)
		case errors.Is(err, proxycore.ErrHostKeyMismatch):
			tell(clientChannel, shellRequested, hostKeyMismatchMessage)
		}
	}
}

// tell writes a message to the operator, once they have asked for a shell.
// A refusal comes fast — the recorder is checked before anything else — and
// an SSH client that is still negotiating its pty and shell when the channel
// is closed sees "connection closed" and never the reason. So wait (briefly:
// a client that never asks for a shell is not owed the wait) for the shell
// request, then write.
func tell(ch ssh.Channel, shellRequested <-chan struct{}, msg string) {
	select {
	case <-shellRequested:
	case <-time.After(2 * time.Second):
	}
	fmt.Fprint(ch, msg)
}

// sessionStart is what the client asked its session channel to run (ADR-0038).
type sessionStart struct {
	mode sshcodec.Mode
	scp  sshcodec.SCPCommand
}

// acceptSessionChannel accepts the first "session"-type channel the client opens and answers
// its requests: pty-req, env and window-change are taken; the first of shell, the "sftp"
// subsystem, or an exec of exactly a legacy scp sink or source (sshcodec.ParseSCPCommand)
// starts the session — anything else (another command, another subsystem) is refused, as
// before ADR-0038.
//
// The returned start channel delivers what was asked, once; shellRequested is closed then too
// (tell waits on it).
func acceptSessionChannel(chans <-chan ssh.NewChannel) (ssh.Channel, func(), <-chan struct{}, <-chan sessionStart, error) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only session channels are supported")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return nil, nil, nil, nil, fmt.Errorf("accepting session channel: %w", err)
		}
		shellRequested := make(chan struct{})
		start := make(chan sessionStart, 1)
		var once sync.Once
		begin := func(s sessionStart) bool {
			started := false
			once.Do(func() {
				start <- s
				started = true
			})
			return started
		}
		go func() {
			for req := range requests {
				ok := false
				started := false
				switch req.Type {
				case "pty-req", "env", "window-change":
					ok = true
				case "shell":
					started = begin(sessionStart{mode: sshcodec.ModeShell})
					ok = started
				case "subsystem":
					var p struct{ Name string }
					if ssh.Unmarshal(req.Payload, &p) == nil && p.Name == "sftp" {
						started = begin(sessionStart{mode: sshcodec.ModeSFTP})
						ok = started
					}
				case "exec":
					var p struct{ Command string }
					if ssh.Unmarshal(req.Payload, &p) == nil {
						if c, accepted := sshcodec.ParseSCPCommand(p.Command); accepted {
							started = begin(sessionStart{mode: sshcodec.ModeSCP, scp: c})
							ok = started
						}
					}
				}
				if req.WantReply {
					_ = req.Reply(ok, nil)
				}
				// Do not let session handling close the channel or write a refusal
				// before the client has received the reply to its start request.
				if started {
					close(shellRequested)
				}
			}
		}()
		return ch, func() { _ = ch.Close() }, shellRequested, start, nil
	}
	return nil, nil, nil, nil, fmt.Errorf("client closed connection before opening a session channel")
}

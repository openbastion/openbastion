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
	Listener    *proxycore.Listener // owns credential fetch + purge + audit (doc 01 §4.1)
	DialTimeout time.Duration
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

	clientChannel, cleanup, shellRequested, err := acceptSessionChannel(chans)
	if err != nil {
		log.Printf("ssh-proxy: %v", err)
		return
	}
	defer cleanup()

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
		TargetUser: resolved.TargetUser,
		Recorder:   recordingTap,
		// The target's output feeds the tap's secret-prompt detection, so a
		// sudo password typed next is recorded as redacted, not in the clear.
		OutputObserver: recordingTap.Output(),
		DialTimeout:    s.DialTimeout,
	}

	if err := s.Listener.Serve(ctx, meta, codec, clientChannel, targetConn); err != nil {
		log.Printf("ssh-proxy: session %s: %v", meta.SessionID, err)
		switch {
		case errors.Is(err, proxycore.ErrRecordingUnavailable):
			tell(clientChannel, shellRequested, recordingRefusedMessage)
		case errors.Is(err, proxycore.ErrSessionExpired):
			tell(clientChannel, shellRequested, sessionExpiredMessage)
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

// acceptSessionChannel accepts the first "session"-type channel the
// client opens and answers the handful of requests a normal interactive
// `ssh host` client sends (pty-req, shell, env, window-change) — enough
// for an interactive shell; exec and subsystem (SFTP/SCP) requests are a
// follow-up increment (see /NOTES_SANDBOX.md).
//
// The returned channel is closed when the client asks for a shell.
func acceptSessionChannel(chans <-chan ssh.NewChannel) (ssh.Channel, func(), <-chan struct{}, error) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only interactive session channels are supported in this increment")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return nil, nil, nil, fmt.Errorf("accepting session channel: %w", err)
		}
		shellRequested := make(chan struct{})
		var shellOnce sync.Once
		go func() {
			for req := range requests {
				switch req.Type {
				case "shell", "pty-req", "env", "window-change":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
					if req.Type == "shell" {
						shellOnce.Do(func() { close(shellRequested) })
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
		return ch, func() { _ = ch.Close() }, shellRequested, nil
	}
	return nil, nil, nil, fmt.Errorf("client closed connection before opening a session channel")
}

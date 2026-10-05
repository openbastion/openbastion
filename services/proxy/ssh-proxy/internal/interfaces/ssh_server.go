// Package interfaces holds the SSH Proxy's two inbound surfaces: the real
// SSH listener (this file) that terminates client connections, and the
// HTTP implementation of ProxyControl (http.go) that the Session Broker
// calls to authorize a pending session.
package interfaces

import (
	"context"
	"fmt"
	"log"
	"net"
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

	clientChannel, cleanup, err := acceptSessionChannel(chans)
	if err != nil {
		log.Printf("ssh-proxy: %v", err)
		return
	}
	defer cleanup()

	targetAddr := resolved.TargetHost
	targetConn, err := net.Dial("tcp", targetAddr)
	if err != nil {
		fmt.Fprintf(clientChannel, "openbastion: cannot reach target %s: %v\r\n", targetAddr, err)
		return
	}
	defer targetConn.Close()

	meta := proxycore.SessionMetadata{
		SessionID:  resolved.SessionID,
		TargetHost: resolved.TargetHost,
		ScopeToken: resolved.ScopeToken,
		ExpiresAt:  resolved.ExpiresAt,
	}
	recordingTap := proxycore.NewRecordingTap(infrastructure.StdoutRecorder{}, resolved.SessionID)
	codec := &sshcodec.Codec{
		TargetUser:  resolved.TargetUser,
		Recorder:    recordingTap,
		DialTimeout: s.DialTimeout,
	}

	if err := s.Listener.Serve(ctx, meta, codec, clientChannel, targetConn); err != nil {
		log.Printf("ssh-proxy: session %s: %v", meta.SessionID, err)
	}
}

// acceptSessionChannel accepts the first "session"-type channel the
// client opens and answers the handful of requests a normal interactive
// `ssh host` client sends (pty-req, shell, env, window-change) — enough
// for an interactive shell; exec and subsystem (SFTP/SCP) requests are a
// follow-up increment (see /NOTES_SANDBOX.md).
func acceptSessionChannel(chans <-chan ssh.NewChannel) (ssh.Channel, func(), error) {
	for newCh := range chans {
		if newCh.ChannelType() != "session" {
			_ = newCh.Reject(ssh.UnknownChannelType, "only interactive session channels are supported in this increment")
			continue
		}
		ch, requests, err := newCh.Accept()
		if err != nil {
			return nil, nil, fmt.Errorf("accepting session channel: %w", err)
		}
		go func() {
			for req := range requests {
				switch req.Type {
				case "shell", "pty-req", "env", "window-change":
					if req.WantReply {
						_ = req.Reply(true, nil)
					}
				default:
					if req.WantReply {
						_ = req.Reply(false, nil)
					}
				}
			}
		}()
		return ch, func() { _ = ch.Close() }, nil
	}
	return nil, nil, fmt.Errorf("client closed connection before opening a session channel")
}

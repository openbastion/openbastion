// Package sshcodec_test proves the real SSH relay end-to-end: a genuine
// golang.org/x/crypto/ssh client (playing the operator) connects through
// a genuine ssh-proxy connection handler, which fetches a credential from
// a fake Vault and authenticates onward to a genuine fake target SSH
// server — three real SSH protocol participants, in-process, no
// subprocesses needed since this is a single module's own test.
package sshcodec_test

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

// -- fake target SSH server ---------------------------------------------
//
// Validates the password it receives EXACTLY matches the secret the test
// onboarded — this is what proves the proxy actually injected the fetched
// credential, not a stand-in. On "shell", it echoes each line it reads
// back prefixed with "echo:", enough to prove bytes flow both ways
// through the proxy correctly.

func startFakeTargetSSHServer(t *testing.T, expectedPassword string) (addr string) {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("target host key: %v", err)
	}
	signer, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatalf("target signer: %v", err)
	}

	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			if string(password) != expectedPassword {
				return nil, fmt.Errorf("wrong password")
			}
			return nil, nil
		},
	}
	config.AddHostKey(signer)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("target listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sshConn, chans, reqs, err := ssh.NewServerConn(conn, config)
				if err != nil {
					return
				}
				defer sshConn.Close()
				go ssh.DiscardRequests(reqs)
				for newCh := range chans {
					if newCh.ChannelType() != "session" {
						_ = newCh.Reject(ssh.UnknownChannelType, "unsupported")
						continue
					}
					ch, requests, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range requests {
							if req.Type == "shell" || req.Type == "pty-req" {
								if req.WantReply {
									_ = req.Reply(true, nil)
								}
							} else if req.WantReply {
								_ = req.Reply(false, nil)
							}
						}
					}()
					go func(ch ssh.Channel) {
						defer ch.Close()
						scanner := bufio.NewScanner(ch)
						for scanner.Scan() {
							fmt.Fprintf(ch, "echo:%s\r\n", scanner.Text())
						}
					}(ch)
				}
			}()
		}
	}()

	return ln.Addr().String()
}

// -- fakes for the ssh-proxy's own outbound dependencies ----------------

type fakeVault struct {
	expectedScopeToken string
	secret             string
}

func (f *fakeVault) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (string, []byte, error) {
	if scopeToken != f.expectedScopeToken {
		return "", nil, fmt.Errorf("unexpected scope token")
	}
	return "password", []byte(f.secret), nil
}

type fakeAudit struct{ events []string }

func (f *fakeAudit) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	f.events = append(f.events, action)
	return nil
}

// -- the test -------------------------------------------------------------

func TestSSHProxy_RealClientThroughRealProxyToRealTarget(t *testing.T) {
	const secretPassword = "target-real-secret-42"
	const scopeToken = "scope-token-for-this-test"

	targetAddr := startFakeTargetSSHServer(t, secretPassword)

	vault := &fakeVault{expectedScopeToken: scopeToken, secret: secretPassword}
	audit := &fakeAudit{}
	fetcher := proxycore.NewCredentialFetcher(vault, "ssh-proxy")
	terminator := proxycore.NewTerminator(audit)
	listener := proxycore.NewListener(fetcher, terminator)

	pending := infrastructure.NewPendingSessions()
	ticket := pending.Register(&infrastructure.PendingSession{
		SessionID:  "session-sshcodec-it",
		TargetHost: targetAddr,
		TargetUser: "root",
		ScopeToken: scopeToken,
		ExpiresAt:  time.Now().UTC().Add(time.Minute),
	})

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("proxy host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("proxy signer: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

	server := &interfaces.SSHServer{
		HostSigner:  hostSigner,
		Pending:     pending,
		Listener:    listener,
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, proxyLn) }()

	// -- the operator: a real ssh.Client authenticating with the ticket --
	clientConfig := &ssh.ClientConfig{
		User:            "operator", // irrelevant to the proxy; only the ticket matters
		Auth:            []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", proxyLn.Addr().String(), clientConfig)
	if err != nil {
		t.Fatalf("client dial to proxy: %v", err)
	}
	defer client.Close()

	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	defer session.Close()

	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatalf("client pty: %v", err)
	}
	stdin, err := session.StdinPipe()
	if err != nil {
		t.Fatalf("client stdin: %v", err)
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		t.Fatalf("client stdout: %v", err)
	}
	if err := session.Shell(); err != nil {
		t.Fatalf("client shell: %v", err)
	}

	if _, err := fmt.Fprintf(stdin, "hello-through-the-proxy\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}

	reader := bufio.NewReader(stdout)
	deadline := time.Now().Add(5 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		line, err = reader.ReadString('\n')
		if err == nil && strings.Contains(line, "echo:hello-through-the-proxy") {
			break
		}
	}
	if !strings.Contains(line, "echo:hello-through-the-proxy") {
		t.Fatalf("expected echo of the command through proxy -> target -> proxy -> client, got %q (err=%v)", line, err)
	}
}

func TestSSHProxy_RejectsClientWithInvalidTicket(t *testing.T) {
	vault := &fakeVault{expectedScopeToken: "irrelevant", secret: "irrelevant"}
	audit := &fakeAudit{}
	listener := proxycore.NewListener(proxycore.NewCredentialFetcher(vault, "ssh-proxy"), proxycore.NewTerminator(audit))
	pending := infrastructure.NewPendingSessions() // nothing registered

	_, hostPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("proxy host key: %v", err)
	}
	hostSigner, err := ssh.NewSignerFromKey(hostPriv)
	if err != nil {
		t.Fatalf("proxy signer: %v", err)
	}

	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

	server := &interfaces.SSHServer{HostSigner: hostSigner, Pending: pending, Listener: listener, DialTimeout: 5 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, proxyLn) }()

	clientConfig := &ssh.ClientConfig{
		User:            "operator",
		Auth:            []ssh.AuthMethod{ssh.Password("this-ticket-was-never-issued")},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	if _, err := ssh.Dial("tcp", proxyLn.Addr().String(), clientConfig); err == nil {
		t.Fatal("expected the SSH handshake to fail for an unregistered connection ticket")
	}
}

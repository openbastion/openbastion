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
	"sync"
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
	return startObservedFakeTargetSSHServer(t, expectedPassword, nil)
}

// startObservedFakeTargetSSHServer is the same target, additionally reporting
// every line it receives — the moment the "command" reaches the target — to
// onLine (nil means no reporting). It is how the record-or-refuse tests see
// what the target was actually sent.
func startObservedFakeTargetSSHServer(t *testing.T, expectedPassword string, onLine func(line string)) (addr string) {
	t.Helper()
	return startKeyedFakeTargetSSHServer(t, targetHostSigner, expectedPassword, onLine)
}

// targetHostSigner is the host key of every fake target, the one fakeVault pins (ADR-0039).
var targetHostSigner = func() ssh.Signer {
	s, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize)))
	if err != nil {
		panic(err)
	}
	return s
}()

// targetHostKey is targetHostSigner's public key as the Vault stores it.
var targetHostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(targetHostSigner.PublicKey())))

// startKeyedFakeTargetSSHServer is the same target presenting the host key signer.
func startKeyedFakeTargetSSHServer(t *testing.T, signer ssh.Signer, expectedPassword string, onLine func(line string)) (addr string) {
	t.Helper()
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
							text := scanner.Text()
							if onLine != nil {
								onLine(text)
							}
							if text == "sudo -s" {
								// Behave like a real sudo: a prompt with no trailing
								// newline, then the next line is the password, which
								// is NOT echoed (the terminal's echo is off).
								fmt.Fprint(ch, "[sudo] password for root: ")
								if !scanner.Scan() {
									return
								}
								fmt.Fprint(ch, "\r\nroot-shell-ready\r\n")
								continue
							}
							fmt.Fprintf(ch, "echo:%s\r\n", text)
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
	// hostKey is the key the Vault pinned for the target: empty means targetHostKey,
	// noHostKey that the Vault gives none; targetHost the address it gives the secret for.
	hostKey    string
	noHostKey  bool
	targetHost string
}

func (f *fakeVault) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (proxycore.Fetched, error) {
	if scopeToken != f.expectedScopeToken {
		return proxycore.Fetched{}, fmt.Errorf("unexpected scope token")
	}
	key := f.hostKey
	if key == "" {
		key = targetHostKey
	}
	if f.noHostKey {
		key = ""
	}
	return proxycore.Fetched{Type: "password", Material: []byte(f.secret), TargetHost: f.targetHost, HostKey: key}, nil
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
	listener.Recording = proxycore.RecordingConfig{Policy: proxycore.RecordingBestEffort} // this test is about the relay, not recording

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

// recordedCommands is a proxycore.Recorder that keeps what it was given.
type recordedCommands struct {
	mu      sync.Mutex
	entries []proxycore.CommandEntry
}

func (r *recordedCommands) Record(ctx context.Context, e proxycore.CommandEntry) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.entries = append(r.entries, e)
	return nil
}

func (r *recordedCommands) commands() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, 0, len(r.entries))
	for _, e := range r.entries {
		out = append(out, e.Command)
	}
	return out
}

// An interactive client with a PTY sends '\r' for Enter. The command must
// reach the Recorder through the real SSH stack, attributed to the right
// session, and what the operator types at a target's secret prompt must
// not be stored.
func TestSSHProxy_InteractiveCommandsAreRecordedAndSecretPromptInputIsRedacted(t *testing.T) {
	const secretPassword = "target-real-secret-42"
	const scopeToken = "scope-token-recording"

	targetAddr := startFakeTargetSSHServer(t, secretPassword)

	listener := proxycore.NewListener(
		proxycore.NewCredentialFetcher(&fakeVault{expectedScopeToken: scopeToken, secret: secretPassword}, "ssh-proxy"),
		proxycore.NewTerminator(&fakeAudit{}),
	)
	pending := infrastructure.NewPendingSessions()
	ticket := pending.Register(&infrastructure.PendingSession{
		SessionID: "session-recorded", TargetHost: targetAddr, TargetUser: "root",
		ScopeToken: scopeToken, ExpiresAt: time.Now().UTC().Add(time.Minute),
	})

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostSigner, _ := ssh.NewSignerFromKey(hostPriv)
	proxyLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("proxy listen: %v", err)
	}
	t.Cleanup(func() { _ = proxyLn.Close() })

	recorder := &recordedCommands{}
	// This test is about WHAT is captured, not about what happens when capture
	// fails (see strict_recording_test.go), so it runs best-effort, explicitly.
	listener.Recording = proxycore.RecordingConfig{Policy: proxycore.RecordingBestEffort, Sink: recorder}
	server := &interfaces.SSHServer{
		HostSigner: hostSigner, Pending: pending, Listener: listener,
		DialTimeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = server.Serve(ctx, proxyLn) }()

	client, err := ssh.Dial("tcp", proxyLn.Addr().String(), &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
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
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil {
		t.Fatalf("client shell: %v", err)
	}

	// A pump goroutine accumulates the target's output, byte by byte —
	// a prompt has no trailing newline, so line reads would never see it.
	// Waiting on the OUTPUT is also what makes the order below
	// deterministic: the codec feeds the secret-prompt detector before it
	// forwards the same bytes to the client.
	var (
		outMu  sync.Mutex
		outBuf strings.Builder
	)
	go func() {
		one := make([]byte, 1)
		for {
			n, err := stdout.Read(one)
			if n > 0 {
				outMu.Lock()
				outBuf.Write(one[:n])
				outMu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	waitFor := func(want string) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			outMu.Lock()
			ok := strings.Contains(outBuf.String(), want)
			outMu.Unlock()
			if ok {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatalf("never saw %q from the target", want)
	}

	// '\r' is what a real terminal sends; the fake target reads lines, so
	// each is followed by '\n', as a PTY's CR-to-NL translation would.
	fmt.Fprint(stdin, "whoami\r\n")
	waitFor("echo:whoami")
	fmt.Fprint(stdin, "sudo -s\r\n")
	waitFor("[sudo] password for root: ")
	fmt.Fprint(stdin, "hunter2\r\n")
	waitFor("root-shell-ready")
	fmt.Fprint(stdin, "id\r\n")
	waitFor("echo:id")

	got := recorder.commands()
	for _, c := range got {
		if c == "hunter2" {
			t.Fatalf("the line typed after the prompt was stored in the clear: %q", got)
		}
	}
	want := []string{"whoami", "sudo -s", proxycore.RedactedSecretInput, "id"}
	if len(got) != len(want) {
		t.Fatalf("expected %q, got %q", want, got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("expected %q, got %q", want, got)
		}
	}
	for _, e := range recorder.entries {
		if e.SessionID != "session-recorded" {
			t.Fatalf("entry attributed to the wrong session: %+v", e)
		}
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

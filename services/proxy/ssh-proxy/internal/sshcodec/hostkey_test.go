package sshcodec_test

// The target's host key is pinned (ADR-0039): the proxy sends the secret only to the target
// that presents the key the Vault stored with it. A machine that takes the target's place —
// on the network, in DNS, behind a stolen address — has another key and gets no password.

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/sshcodec"
)

// passwordTarget is an SSH server presenting signer that records every password offered.
type passwordTarget struct {
	addr string
	mu   sync.Mutex
	seen []string
}

func (p *passwordTarget) passwords() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.seen...)
}

func startPasswordTarget(t *testing.T, signer ssh.Signer) *passwordTarget {
	t.Helper()
	p := &passwordTarget{}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, password []byte) (*ssh.Permissions, error) {
			p.mu.Lock()
			p.seen = append(p.seen, string(password))
			p.mu.Unlock()
			return nil, nil
		},
	}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
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
					ch, requests, err := newCh.Accept()
					if err != nil {
						return
					}
					go func() {
						for req := range requests {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
						}
					}()
					go func() { _, _ = ch.Read(make([]byte, 1)); _ = ch.Close() }()
				}
			}()
		}
	}()
	p.addr = ln.Addr().String()
	return p
}

// relayTo runs the codec against addr with the credential vault gives, the session naming
// sessionHost.
func relayTo(t *testing.T, vault *fakeVault, addr, sessionHost string) error {
	t.Helper()
	cred, err := proxycore.NewCredentialFetcher(vault, "ssh-proxy").Fetch(context.Background(), vault.expectedScopeToken)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// An operator who types nothing (the shell ends at once) and whose screen is not read.
	return (&sshcodec.Codec{TargetUser: "root", TargetHost: sessionHost, DialTimeout: 3 * time.Second}).Relay(ctx, quietClient{}, conn, cred)
}

// quietClient reads nothing and discards what it is shown: safe from both relay goroutines.
type quietClient struct{}

func (quietClient) Read([]byte) (int, error)    { return 0, io.EOF }
func (quietClient) Write(p []byte) (int, error) { return len(p), nil }

func otherSigner(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// Attack: an impostor with another host key takes the target's place. Counter-proof: the
// real target, with the pinned key, receives the secret.
func TestRelay_AnImpostorWithAnotherHostKeyIsSentNoSecret(t *testing.T) {
	const secret = "the-target-root-password"
	vault := &fakeVault{expectedScopeToken: "scope", secret: secret}

	impostor := startPasswordTarget(t, otherSigner(t))
	err := relayTo(t, vault, impostor.addr, "")
	if !errors.Is(err, sshcodec.ErrHostKeyMismatch) {
		t.Fatalf("an impostor's host key was accepted: Relay returned %v", err)
	}
	if got := impostor.passwords(); len(got) != 0 {
		t.Fatalf("the impostor was sent %d password(s): %q", len(got), got)
	}
	if !strings.Contains(err.Error(), ssh.FingerprintSHA256(targetHostSigner.PublicKey())) {
		t.Fatalf("the refusal does not name the pinned fingerprint: %v", err)
	}

	real := startPasswordTarget(t, targetHostSigner)
	if err := relayTo(t, vault, real.addr, ""); err != nil {
		t.Fatalf("the pinned target was refused: %v", err)
	}
	if got := real.passwords(); len(got) != 1 || got[0] != secret {
		t.Fatalf("the pinned target was not sent the secret: %q", got)
	}
}

// A credential that comes without a pinned key — or with one that does not read — is used
// for nothing: no handshake is even started.
func TestRelay_NoPinnedHostKeyMeansNoSecret(t *testing.T) {
	for name, vault := range map[string]*fakeVault{
		"no key":          {expectedScopeToken: "scope", secret: "pw", noHostKey: true},
		"unreadable key":  {expectedScopeToken: "scope", secret: "pw", hostKey: "ssh-ed25519 not-base64"},
		"a key, not mine": {expectedScopeToken: "scope", secret: "pw", hostKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(otherSigner(t).PublicKey())))},
	} {
		t.Run(name, func(t *testing.T) {
			target := startPasswordTarget(t, targetHostSigner)
			if err := relayTo(t, vault, target.addr, ""); !errors.Is(err, sshcodec.ErrHostKeyMismatch) {
				t.Fatalf("Relay returned %v, want ErrHostKeyMismatch", err)
			}
			if got := target.passwords(); len(got) != 0 {
				t.Fatalf("the target was sent %d password(s)", len(got))
			}
		})
	}
}

// The session must go where the Vault gave the secret for: a Broker (or anything between)
// that names another address does not get the secret used against it.
func TestRelay_ASessionNamingAnotherHostThanTheVaultsIsRefused(t *testing.T) {
	target := startPasswordTarget(t, targetHostSigner)
	vault := &fakeVault{expectedScopeToken: "scope", secret: "pw", targetHost: "10.0.0.5:22"}

	err := relayTo(t, vault, target.addr, target.addr)
	if !errors.Is(err, sshcodec.ErrHostKeyMismatch) {
		t.Fatalf("a session naming %s for a secret given for 10.0.0.5:22 went on: %v", target.addr, err)
	}
	if got := target.passwords(); len(got) != 0 {
		t.Fatalf("the target was sent %d password(s)", len(got))
	}

	// Counter-proof: the same address on both sides.
	vault.targetHost = target.addr
	if err := relayTo(t, vault, target.addr, target.addr); err != nil {
		t.Fatalf("the Vault's own target was refused: %v", err)
	}
	if got := target.passwords(); len(got) != 1 {
		t.Fatalf("the Vault's own target was sent %d password(s)", len(got))
	}
}

// throughTheProxy runs one shell session through the real SSHServer, the Broker naming
// sessionHost, and returns what the operator read and what was audited.
func throughTheProxy(t *testing.T, vault *fakeVault, sessionHost string) (string, []string) {
	t.Helper()
	audit := &fakeAudit{}
	listener := proxycore.NewListener(proxycore.NewCredentialFetcher(vault, "ssh-proxy"), proxycore.NewTerminator(audit))
	listener.Recording = proxycore.RecordingConfig{Policy: proxycore.RecordingBestEffort}
	pending := infrastructure.NewPendingSessions()
	ticket := pending.Register(&infrastructure.PendingSession{SessionID: "s-pin", TargetHost: sessionHost, TargetUser: "root",
		ScopeToken: vault.expectedScopeToken, ExpiresAt: time.Now().UTC().Add(time.Minute)})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	defer ln.Close()
	go func() {
		_ = (&interfaces.SSHServer{HostSigner: otherSigner(t), Pending: pending, Listener: listener, DialTimeout: 3 * time.Second}).Serve(ctx, ln)
	}()
	client, err := ssh.Dial("tcp", ln.Addr().String(), &ssh.ClientConfig{User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	session.Stdout = &out
	if err := session.Shell(); err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() { _ = session.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
	}
	return out.String(), audit.events
}

// The address the Broker names reaches the codec from the real SSHServer: a session for an
// address other than the Vault's gets no secret, the operator is told, the audit records it.
func TestSSHServer_TheSessionsAddressIsCheckedAgainstTheVaults(t *testing.T) {
	target := startPasswordTarget(t, targetHostSigner)
	vault := &fakeVault{expectedScopeToken: "scope", secret: "pw", targetHost: "10.9.9.9:22"}
	out, events := throughTheProxy(t, vault, target.addr)
	if got := target.passwords(); len(got) != 0 {
		t.Fatalf("the target was sent %d password(s) for a secret given for 10.9.9.9:22", len(got))
	}
	if !strings.Contains(out, "pinned host key") {
		t.Fatalf("the operator was not told: %q", out)
	}
	if strings.Join(events, ",") != "session.host_key_mismatch,session.terminate" {
		t.Fatalf("audited %v", events)
	}

	vault.targetHost = target.addr
	if _, events := throughTheProxy(t, vault, target.addr); strings.Contains(strings.Join(events, ","), "mismatch") {
		t.Fatalf("the Vault's own address was refused: %v", events)
	}
	if got := target.passwords(); len(got) != 1 {
		t.Fatalf("the Vault's own target was sent %d password(s)", len(got))
	}
}

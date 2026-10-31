package infrastructure_test

// Setting and verifying a password on a real SSH server (ADR-0037): chpasswd as root, through
// sudo -S otherwise, the secret on standard input only.

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

type sshTarget struct {
	addr     string
	hostKey  string   // its public host key, as pinned (ADR-0039)
	logins   []string // every password it was offered
	mu       sync.Mutex
	pw       map[string]string
	sudoers  map[string]bool
	commands []string
}

func newSigner() ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	return signer
}

func startSSHTarget(t *testing.T) *sshTarget { return startSSHTargetWith(t, newSigner()) }

// startSSHTargetWith serves with signer as its host key — a plain key, or a certificate.
func startSSHTargetWith(t *testing.T, signer ssh.Signer) *sshTarget {
	t.Helper()
	tgt := &sshTarget{pw: map[string]string{"root": "root-pw", "ops": "ops-pw", "app": "old-pw", "nobody": "n-pw"}, sudoers: map[string]bool{"ops": true}}
	tgt.hostKey = strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		tgt.mu.Lock()
		defer tgt.mu.Unlock()
		tgt.logins = append(tgt.logins, string(p))
		if want, ok := tgt.pw[m.User()]; ok && want == string(p) {
			return &ssh.Permissions{Extensions: map[string]string{"user": m.User()}}, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	tgt.addr = ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go tgt.serve(c, cfg)
		}
	}()
	return tgt
}

func (tgt *sshTarget) serve(c net.Conn, cfg *ssh.ServerConfig) {
	conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		return
	}
	defer conn.Close()
	go ssh.DiscardRequests(reqs)
	user := conn.Permissions.Extensions["user"]
	for nc := range chans {
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			defer ch.Close()
			for r := range requests {
				if r.Type != "exec" {
					_ = r.Reply(false, nil)
					continue
				}
				_ = r.Reply(true, nil)
				cmd := string(r.Payload[4:])
				status := tgt.run(user, cmd, ch)
				_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
				return
			}
		}()
	}
}

func (tgt *sshTarget) run(user, cmd string, ch ssh.Channel) uint32 {
	tgt.mu.Lock()
	tgt.commands = append(tgt.commands, cmd)
	tgt.mu.Unlock()
	in := bufio.NewReader(ch)
	switch {
	case cmd == "chpasswd" && user == "root":
	case cmd == "sudo -S -p '' chpasswd" && tgt.sudoers[user]:
		line, _ := in.ReadString('\n')
		tgt.mu.Lock()
		ok := strings.TrimRight(line, "\n") == tgt.pw[user]
		tgt.mu.Unlock()
		if !ok {
			_, _ = io.WriteString(ch.Stderr(), "sudo: incorrect password")
			return 1
		}
	default:
		_, _ = io.WriteString(ch.Stderr(), "chpasswd: permission denied")
		return 1
	}
	line, _ := in.ReadString('\n')
	u, p, ok := strings.Cut(strings.TrimRight(line, "\n"), ":")
	if !ok {
		return 1
	}
	tgt.mu.Lock()
	tgt.pw[u] = p
	tgt.mu.Unlock()
	return 0
}

func TestSSHTargetChanger_SetsThePasswordAsRootOrThroughSudo_AndVerifies(t *testing.T) {
	tgt := startSSHTarget(t)
	c := infrastructure.SSHTargetChanger{}
	ctx := context.Background()
	if err := c.SetPassword(ctx, tgt.addr, tgt.hostKey, "root", []byte("root-pw"), "app", []byte("new-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, tgt.addr, tgt.hostKey, "app", []byte("new-1")); err != nil {
		t.Fatalf("verify the new secret: %v", err)
	}
	if err := c.Verify(ctx, tgt.addr, tgt.hostKey, "app", []byte("old-pw")); err == nil {
		t.Fatal("the old secret still opens the target")
	}
	if err := c.SetPassword(ctx, tgt.addr, tgt.hostKey, "ops", []byte("ops-pw"), "app", []byte("new-2")); err != nil {
		t.Fatalf("through sudo: %v", err)
	}
	if err := c.Verify(ctx, tgt.addr, tgt.hostKey, "app", []byte("new-2")); err != nil {
		t.Fatal(err)
	}
	for _, cmd := range tgt.commands {
		if strings.Contains(cmd, "new-") || strings.Contains(cmd, "-pw") {
			t.Fatalf("a secret on the command line: %q", cmd)
		}
	}
}

func TestSSHTargetChanger_ARefusalIsAnError(t *testing.T) {
	tgt := startSSHTarget(t)
	c := infrastructure.SSHTargetChanger{}
	ctx := context.Background()
	for name, try := range map[string]func() error{
		"a wrong reconciliation secret": func() error {
			return c.SetPassword(ctx, tgt.addr, tgt.hostKey, "root", []byte("nope"), "app", []byte("x"))
		},
		"an account that may not sudo": func() error {
			return c.SetPassword(ctx, tgt.addr, tgt.hostKey, "nobody", []byte("n-pw"), "app", []byte("x"))
		},
		"nothing listening": func() error {
			return c.SetPassword(ctx, "127.0.0.1:1", tgt.hostKey, "root", []byte("root-pw"), "app", []byte("x"))
		},
		"a secret the target refuses": func() error { return c.Verify(ctx, tgt.addr, tgt.hostKey, "app", []byte("wrong")) },
	} {
		if err := try(); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
	if tgt.pw["app"] != "old-pw" {
		t.Fatal("the password changed after refusals")
	}
}

// ADR-0039: a server that does not present the pinned host key — someone in between — is
// offered no secret at all: neither the reconciliation account's nor the new one.
func TestSSHTargetChanger_AnotherHostKeyIsOfferedNoSecret(t *testing.T) {
	tgt := startSSHTarget(t)
	impostor := startSSHTarget(t) // same accounts, another host key
	c := infrastructure.SSHTargetChanger{}
	ctx := context.Background()
	if err := c.SetPassword(ctx, impostor.addr, tgt.hostKey, "root", []byte("root-pw"), "app", []byte("new-secret")); err == nil {
		t.Fatal("a server with another host key took the change")
	}
	if err := c.Verify(ctx, impostor.addr, tgt.hostKey, "app", []byte("old-pw")); err == nil {
		t.Fatal("a server with another host key was verified")
	}
	impostor.mu.Lock()
	defer impostor.mu.Unlock()
	if len(impostor.logins) != 0 || impostor.pw["app"] != "old-pw" {
		t.Fatalf("the impostor was offered %d password(s): %q", len(impostor.logins), impostor.logins)
	}
	if err := c.SetPassword(ctx, tgt.addr, "not a key", "root", []byte("root-pw"), "app", []byte("x")); err == nil {
		t.Fatal("no usable pinned key, and the change went through")
	}
}

// hostCertSigner is a fresh host key certified by ca for name, valid an hour around now.
func hostCertSigner(t *testing.T, ca ssh.Signer, name string) ssh.Signer {
	t.Helper()
	host := newSigner()
	cert := &ssh.Certificate{Key: host.PublicKey(), CertType: ssh.HostCert, ValidPrincipals: []string{name},
		ValidAfter: uint64(time.Now().Add(-time.Hour).Unix()), ValidBefore: uint64(time.Now().Add(time.Hour).Unix())}
	if err := cert.SignCert(rand.Reader, ca); err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewCertSigner(cert, host)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// ADR-0048: an account recognising its target by an authority rotates against a target that
// presents a certificate of that authority for the account's name, and offers no secret to one
// certified by another authority, or for another name.
func TestSSHTargetChanger_ByAuthority_TheCertifiedTargetRotates_NoImpostorIsOfferedASecret(t *testing.T) {
	ca, rogue := newSigner(), newSigner()
	authority := "@cert-authority target.example " + strings.TrimSpace(string(ssh.MarshalAuthorizedKey(ca.PublicKey())))
	c := infrastructure.SSHTargetChanger{}
	ctx := context.Background()

	tgt := startSSHTargetWith(t, hostCertSigner(t, ca, "target.example"))
	if err := c.SetPassword(ctx, tgt.addr, authority, "root", []byte("root-pw"), "app", []byte("new-1")); err != nil {
		t.Fatalf("the certified target refused the change: %v", err)
	}
	if err := c.Verify(ctx, tgt.addr, authority, "app", []byte("new-1")); err != nil {
		t.Fatalf("the certified target: %v", err)
	}
	for name, signer := range map[string]ssh.Signer{
		"a plain key":                 newSigner(),
		"another authority":           hostCertSigner(t, rogue, "target.example"),
		"the authority, another name": hostCertSigner(t, ca, "other.example"),
	} {
		imp := startSSHTargetWith(t, signer)
		if err := c.SetPassword(ctx, imp.addr, authority, "root", []byte("root-pw"), "app", []byte("x")); err == nil {
			t.Fatalf("%s: the change went through", name)
		}
		imp.mu.Lock()
		n := len(imp.logins)
		imp.mu.Unlock()
		if n != 0 {
			t.Fatalf("%s: the impostor was offered %d password(s)", name, n)
		}
	}
}

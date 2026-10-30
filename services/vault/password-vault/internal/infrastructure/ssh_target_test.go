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

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/infrastructure"
)

type sshTarget struct {
	addr     string
	mu       sync.Mutex
	pw       map[string]string
	sudoers  map[string]bool
	commands []string
}

func startSSHTarget(t *testing.T) *sshTarget {
	t.Helper()
	tgt := &sshTarget{pw: map[string]string{"root": "root-pw", "ops": "ops-pw", "app": "old-pw", "nobody": "n-pw"}, sudoers: map[string]bool{"ops": true}}
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, _ := ssh.NewSignerFromKey(priv)
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		tgt.mu.Lock()
		defer tgt.mu.Unlock()
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
	if err := c.SetPassword(ctx, tgt.addr, "root", []byte("root-pw"), "app", []byte("new-1")); err != nil {
		t.Fatal(err)
	}
	if err := c.Verify(ctx, tgt.addr, "app", []byte("new-1")); err != nil {
		t.Fatalf("verify the new secret: %v", err)
	}
	if err := c.Verify(ctx, tgt.addr, "app", []byte("old-pw")); err == nil {
		t.Fatal("the old secret still opens the target")
	}
	if err := c.SetPassword(ctx, tgt.addr, "ops", []byte("ops-pw"), "app", []byte("new-2")); err != nil {
		t.Fatalf("through sudo: %v", err)
	}
	if err := c.Verify(ctx, tgt.addr, "app", []byte("new-2")); err != nil {
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
		"a wrong reconciliation secret": func() error { return c.SetPassword(ctx, tgt.addr, "root", []byte("nope"), "app", []byte("x")) },
		"an account that may not sudo":  func() error { return c.SetPassword(ctx, tgt.addr, "nobody", []byte("n-pw"), "app", []byte("x")) },
		"nothing listening":             func() error { return c.SetPassword(ctx, "127.0.0.1:1", "root", []byte("root-pw"), "app", []byte("x")) },
		"a secret the target refuses":   func() error { return c.Verify(ctx, tgt.addr, "app", []byte("wrong")) },
	} {
		if err := try(); err == nil {
			t.Fatalf("%s: no error", name)
		}
	}
	if tgt.pw["app"] != "old-pw" {
		t.Fatal("the password changed after refusals")
	}
}

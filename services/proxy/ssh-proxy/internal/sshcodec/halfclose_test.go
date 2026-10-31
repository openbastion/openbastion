package sshcodec_test

// An operator whose input ends — `ssh … < /dev/null`, `echo cmd | ssh …` — has said everything
// they will say; they have not hung up. What the target still answers reaches them, until the
// target ends the shell, as with sshd.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/sshcodec"
)

// lateTarget answers a shell with "late answer" after delay, then ends it.
func lateTarget(t *testing.T, delay time.Duration) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(targetHostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, requests, _ := nc.Accept()
					go func() {
						for req := range requests {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
							if req.Type == "shell" {
								go func() {
									time.Sleep(delay)
									fmt.Fprint(ch, "late answer\r\n")
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
									_ = ch.Close()
								}()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// silentClient has nothing to say (its input is at its end) and keeps what it is shown.
type silentClient struct {
	mu  sync.Mutex
	out bytes.Buffer
}

func (*silentClient) Read([]byte) (int, error) { return 0, io.EOF }
func (c *silentClient) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.Write(p)
}
func (c *silentClient) shown() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.out.String()
}

func TestRelay_AnOperatorWhoseInputEnds_StillReadsWhatTheTargetAnswers(t *testing.T) {
	addr := lateTarget(t, 100*time.Millisecond)
	cred, err := proxycore.NewCredentialFetcher(&fakeVault{expectedScopeToken: "scope", secret: "pw"}, "ssh-proxy").Fetch(context.Background(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &silentClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- (&sshcodec.Codec{TargetUser: "root", DialTimeout: 3 * time.Second}).Relay(ctx, client, conn, cred)
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Relay: %v", err)
		}
	case <-time.After(4 * time.Second):
		t.Fatal("the relay did not end when the target ended the shell")
	}
	if got := client.shown(); !bytes.Contains([]byte(got), []byte("late answer")) {
		t.Fatalf("the operator was shown %q: the target's answer was lost", got)
	}
}

// eofTarget answers a shell only once its input ends — as `sort` or `cat` would.
func eofTarget(t *testing.T) string {
	t.Helper()
	cfg := &ssh.ServerConfig{PasswordCallback: func(ssh.ConnMetadata, []byte) (*ssh.Permissions, error) { return nil, nil }}
	cfg.AddHostKey(targetHostSigner)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer sc.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, requests, _ := nc.Accept()
					go func() {
						for req := range requests {
							if req.WantReply {
								_ = req.Reply(true, nil)
							}
							if req.Type == "shell" {
								go func() {
									_, _ = io.Copy(io.Discard, ch) // until the input ends
									fmt.Fprint(ch, "input ended\r\n")
									_, _ = ch.SendRequest("exit-status", false, ssh.Marshal(struct{ C uint32 }{0}))
									_ = ch.Close()
								}()
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// The target is told the operator's input ended: a command that reads to its end answers.
func TestRelay_AnOperatorWhoseInputEnds_TheTargetIsTold(t *testing.T) {
	addr := eofTarget(t)
	cred, err := proxycore.NewCredentialFetcher(&fakeVault{expectedScopeToken: "scope", secret: "pw"}, "ssh-proxy").Fetch(context.Background(), "scope")
	if err != nil {
		t.Fatal(err)
	}
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := &silentClient{}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := (&sshcodec.Codec{TargetUser: "root", DialTimeout: 3 * time.Second}).Relay(ctx, client, conn, cred); err != nil {
		t.Fatalf("Relay: %v (the target was never told the input ended)", err)
	}
	if !bytes.Contains([]byte(client.shown()), []byte("input ended")) {
		t.Fatalf("shown %q", client.shown())
	}
}

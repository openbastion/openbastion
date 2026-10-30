// Command demo-ssh-target is the SSH target of the docker-compose demonstration (ADR-0033): a
// server that accepts one password (DEMO_TARGET_PASSWORD) and runs a pretend shell, which
// echoes what is typed and answers each line with "out:<line>". It is enough to go through the
// whole journey — a session through the proxy, recorded, replayed — without a third-party
// image. It is not a shell: nothing typed is ever executed.
package main

import (
	"bufio"
	"crypto/ed25519"
	"crypto/sha256"
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	password := os.Getenv("DEMO_TARGET_PASSWORD")
	if password == "" {
		log.Fatal("demo-ssh-target: DEMO_TARGET_PASSWORD is required")
	}
	addr := ":" + envOr("DEMO_TARGET_PORT", "2022")
	// The host key stays the same across restarts, as a real server's does, and is printed:
	// the administrator pins it in the Vault (ADR-0039). Derived from the demonstration's own
	// password — this is a demonstration target, not a way to keep a key.
	seed := sha256.Sum256([]byte("openbastion demo-ssh-target host key\x00" + password))
	signer, err := ssh.NewSignerFromKey(ed25519.NewKeyFromSeed(seed[:]))
	if err != nil {
		log.Fatal(err)
	}
	config := &ssh.ServerConfig{
		PasswordCallback: func(meta ssh.ConnMetadata, pw []byte) (*ssh.Permissions, error) {
			if string(pw) != password {
				return nil, fmt.Errorf("wrong password")
			}
			return nil, nil
		},
	}
	config.AddHostKey(signer)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("demo-ssh-target listening on %s (a pretend shell: nothing typed is executed)", addr)
	log.Printf("demo-ssh-target host key: %s", strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))))
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn, config)
	}
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func handle(conn net.Conn, config *ssh.ServerConfig) {
	defer conn.Close()
	_, chans, reqs, err := ssh.NewServerConn(conn, config)
	if err != nil {
		return
	}
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			_ = nc.Reject(ssh.UnknownChannelType, "only sessions")
			continue
		}
		ch, requests, err := nc.Accept()
		if err != nil {
			return
		}
		go func() {
			for r := range requests {
				_ = r.Reply(r.Type == "pty-req" || r.Type == "shell" || r.Type == "window-change", nil)
			}
		}()
		go shell(ch)
	}
}

func shell(ch ssh.Channel) {
	defer ch.Close()
	in := bufio.NewReader(ch)
	for {
		fmt.Fprint(ch, "$ ")
		var line []byte
		for {
			b, err := in.ReadByte()
			if err != nil {
				return
			}
			if b == '\r' || b == '\n' {
				break
			}
			line = append(line, b)
			_, _ = ch.Write([]byte{b})
		}
		if string(line) == "exit" {
			_, _ = ch.SendRequest("exit-status", false, []byte{0, 0, 0, 0})
			return
		}
		fmt.Fprintf(ch, "\r\nout:%s\r\n", line)
	}
}

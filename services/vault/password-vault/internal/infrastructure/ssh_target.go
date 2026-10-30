package infrastructure

// Setting and verifying a password on an SSH target (ADR-0037).

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/crypto/ssh"
)

// SSHTargetChanger is application.TargetChanger over SSH, with password authentication.
//
// The target's host key is NOT verified (ssh.InsecureIgnoreHostKey), exactly as the SSH proxy
// does today (MVP): whoever stands between the Vault and the target sees the new secret and the
// reconciliation account's. ADR-0037 states it.
type SSHTargetChanger struct {
	Timeout time.Duration // per connection; 15 s when zero
}

func (c SSHTargetChanger) dial(ctx context.Context, host, user string, secret []byte) (*ssh.Client, error) {
	timeout := c.Timeout
	if timeout == 0 {
		timeout = 15 * time.Second
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, err
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))
	sc, chans, reqs, err := ssh.NewClientConn(conn, host, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.Password(string(secret))},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // MVP, as the proxy: see the type
		Timeout:         timeout,
	})
	if err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return ssh.NewClient(sc, chans, reqs), nil
}

// SetPassword runs chpasswd on host as admin — through `sudo -S` when admin is not root, the
// admin's secret first on standard input — with "user:newSecret" as its only input line. The
// secret never appears on a command line.
func (c SSHTargetChanger) SetPassword(ctx context.Context, host, admin string, adminSecret []byte, user string, newSecret []byte) error {
	client, err := c.dial(ctx, host, admin, adminSecret)
	if err != nil {
		return fmt.Errorf("the reconciliation account cannot log in to %s: %w", host, err)
	}
	defer client.Close()
	session, err := client.NewSession()
	if err != nil {
		return err
	}
	defer session.Close()
	var in bytes.Buffer
	cmd := "chpasswd"
	if admin != "root" {
		cmd = "sudo -S -p '' chpasswd"
		in.Write(adminSecret)
		in.WriteByte('\n')
	}
	in.WriteString(user + ":")
	in.Write(newSecret)
	in.WriteByte('\n')
	session.Stdin = &in
	var stderr bytes.Buffer
	session.Stderr = &stderr
	if err := session.Run(cmd); err != nil {
		msg := stderr.String()
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("chpasswd on %s failed: %v %s", host, err, msg)
	}
	return nil
}

// Verify logs in to host as user with secret.
func (c SSHTargetChanger) Verify(ctx context.Context, host, user string, secret []byte) error {
	client, err := c.dial(ctx, host, user, secret)
	if err != nil {
		return err
	}
	return client.Close()
}

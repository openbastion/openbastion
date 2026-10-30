package integration_test

// SFTP and SCP through the proxy (ADR-0038), across eight real processes, with the real
// OpenSSH clients (sftp, scp, scp -O) and a target that serves SFTP (github.com/pkg/sftp) and
// runs the real `scp` for the legacy protocol. Before ADR-0038 the proxy refused both: this is
// written first and seen to fail.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

// startTransferTarget serves, for user/password, the sftp subsystem and `scp -t|-f` execs,
// both on the local filesystem.
func startTransferTarget(t *testing.T, user, password string) string {
	t.Helper()
	signer := targetHostSigner // the key every account is pinned to (ADR-0039)
	cfg := &ssh.ServerConfig{PasswordCallback: func(m ssh.ConnMetadata, p []byte) (*ssh.Permissions, error) {
		if m.User() == user && string(p) == password {
			return nil, nil
		}
		return nil, fmt.Errorf("denied")
	}}
	cfg.AddHostKey(signer)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				conn, chans, reqs, err := ssh.NewServerConn(c, cfg)
				if err != nil {
					return
				}
				defer conn.Close()
				go ssh.DiscardRequests(reqs)
				for nc := range chans {
					ch, requests, err := nc.Accept()
					if err != nil {
						return
					}
					go func() {
						defer ch.Close()
						for r := range requests {
							switch r.Type {
							case "subsystem":
								_ = r.Reply(true, nil)
								srv, err := sftp.NewServer(ch)
								if err == nil {
									_ = srv.Serve()
								}
								_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, 0))
								return
							case "exec":
								_ = r.Reply(true, nil)
								args := strings.Fields(string(r.Payload[4:]))
								// A pipe for stdin: Wait then returns when scp exits, not when the
								// channel ends (an sshd sends the exit status as soon as it exits).
								cmd := exec.Command("scp", args[1:]...)
								cmd.Stdout, cmd.Stderr = ch, ch.Stderr()
								stdin, _ := cmd.StdinPipe()
								status := uint32(0)
								if err := cmd.Start(); err != nil {
									status = 1
								} else {
									go func() { _, _ = io.Copy(stdin, ch); _ = stdin.Close() }()
									if err := cmd.Wait(); err != nil {
										status = 1
									}
								}
								_, _ = ch.SendRequest("exit-status", false, binary.BigEndian.AppendUint32(nil, status))
								return
							default:
								_ = r.Reply(r.Type == "env" || r.Type == "pty-req", nil)
							}
						}
					}()
				}
			}()
		}
	}()
	return ln.Addr().String()
}

// openssh runs an OpenSSH client against the proxy, with the connection ticket as password.
func openssh(t *testing.T, ticket string, name string, args ...string) (string, error) {
	t.Helper()
	return opensshIn(t, ticket, "", name, args...)
}

func opensshIn(t *testing.T, ticket, stdin string, name string, args ...string) (string, error) {
	t.Helper()
	dir := t.TempDir()
	askpass := filepath.Join(dir, "askpass.sh")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\necho '"+ticket+"'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	common := []string{"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null", "-o", "PreferredAuthentications=password",
		"-o", "PubkeyAuthentication=no", "-o", "LogLevel=ERROR"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, append(common, args...)...)
	cmd.Env = append(os.Environ(), "SSH_ASKPASS="+askpass, "SSH_ASKPASS_REQUIRE=force", "DISPLAY=none")
	if stdin != "" {
		cmd.Stdin = strings.NewReader(stdin)
	}
	// scp starts an ssh that may hold the output open after the context kills scp: bound the wait.
	cmd.WaitDelay = 5 * time.Second
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func shaHex(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }

func TestTransferFlow_SFTPAndSCPThroughTheProxy_EachTransferRecordedWithItsHash(t *testing.T) {
	for _, bin := range []string{"sftp", "scp"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "proxy": "./services/proxy/ssh-proxy/cmd/ssh-proxy",
		"recorder": "./services/recording-audit/command-recorder/cmd/command-recorder", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-38")
	}
	audit := startService(t, root, bins["audit"], "19602")
	vault := startService(t, root, bins["vault"], "19601", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:19603", "AUDIT_URL="+audit.baseURL)
	authz := startService(t, root, bins["authz"], "19603")
	authn := startService(t, root, bins["authn"], "19607", "SKIP_DEMO_SEED=1")
	startService(t, root, bins["recorder"], "19609", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, bins["proxy"], "19605", "19606", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+audit.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:19609", "RECORDING_POLICY=required")
	broker := startService(t, root, bins["broker"], "19604", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:19605")
	gateway := startService(t, root, bins["gateway"], "19608", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:19609", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL)

	const accountID = "acc_transfer"
	targetAddr := startTransferTarget(t, "app", "app-pw")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "transfer", "app", targetAddr, "app-pw", []string{"vault-admin"})
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	authCreateUser(t, authn.baseURL, "auditor", "Auditor", "aud-password-123", []string{"session-auditor"})
	operatorToken, _ := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")
	auditorToken, _ := gatewayLogin(t, gateway.baseURL, "auditor", "aud-password-123")
	sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create session: %d", status)
	}
	ticket := func(t *testing.T) string {
		t.Helper()
		_, tk, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect: %d", status)
		}
		return tk
	}

	work := t.TempDir()
	remote := t.TempDir() // the target's filesystem is this machine's: the target serves it
	upload := filepath.Join(work, "report.txt")
	content := []byte("the quarterly figures\n" + strings.Repeat("x", 100000))
	if err := os.WriteFile(upload, content, 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("sftp: a put and a get go through, and the target has the file", func(t *testing.T) {
		// Commands on standard input, not -b: batch mode turns password authentication off.
		stdin := fmt.Sprintf("put %s %s/report.txt\nget %s/report.txt %s/back.txt\nmkdir %s/d\nrename %s/report.txt %s/d/r.txt\nbye\n",
			upload, remote, remote, work, remote, remote, remote)
		out, err := opensshIn(t, ticket(t), stdin, "sftp", "-P", "19606", "operator@127.0.0.1")
		if err != nil {
			t.Fatalf("sftp: %v\n%s", err, out)
		}
		got, _ := os.ReadFile(filepath.Join(remote, "d", "r.txt"))
		back, _ := os.ReadFile(filepath.Join(work, "back.txt"))
		if string(got) != string(content) || string(back) != string(content) {
			t.Fatalf("the file did not go through intact (%d and %d bytes)", len(got), len(back))
		}
	})

	t.Run("scp (over sftp, the default) and scp -O (the legacy protocol) go through", func(t *testing.T) {
		if out, err := openssh(t, ticket(t), "scp", "-P", "19606", upload, "operator@127.0.0.1:"+remote+"/via-scp.txt"); err != nil {
			t.Fatalf("scp: %v\n%s", err, out)
		}
		if out, err := openssh(t, ticket(t), "scp", "-O", "-P", "19606", upload, "operator@127.0.0.1:"+remote+"/via-legacy.txt"); err != nil {
			t.Fatalf("scp -O upload: %v\n%s", err, out)
		}
		if out, err := openssh(t, ticket(t), "scp", "-O", "-P", "19606", "operator@127.0.0.1:"+remote+"/via-legacy.txt", filepath.Join(work, "legacy-back.txt")); err != nil {
			t.Fatalf("scp -O download: %v\n%s", err, out)
		}
		for _, f := range []string{filepath.Join(remote, "via-scp.txt"), filepath.Join(remote, "via-legacy.txt"), filepath.Join(work, "legacy-back.txt")} {
			if got, _ := os.ReadFile(f); string(got) != string(content) {
				t.Fatalf("%s: %d bytes, want the file intact", f, len(got))
			}
		}
	})

	t.Run("another command over exec is refused", func(t *testing.T) {
		out, err := openssh(t, ticket(t), "ssh", "-p", "19606", "operator@127.0.0.1", "id")
		if err == nil {
			t.Fatalf("ssh … id went through:\n%s", out)
		}
	})

	t.Run("an auditor reads each transfer, with its size and SHA-256, in the recording", func(t *testing.T) {
		var commands []string
		waitUntil(t, 10*time.Second, "the transfers in the recording", func() bool {
			status, _, page := gatewayGetRecording(t, gateway.baseURL, auditorToken, sess.ID, "?pageSize=200")
			commands = page.commands()
			return status == http.StatusOK && len(commands) >= 8
		})
		all := strings.Join(commands, "\n")
		sum := shaHex(content)
		for _, want := range []string{
			fmt.Sprintf("sftp open %q for writing", remote+"/report.txt"),
			fmt.Sprintf("sftp upload %q (%d bytes, sha256 %s)", remote+"/report.txt", len(content), sum),
			fmt.Sprintf("sftp download %q (%d bytes, sha256 %s)", remote+"/report.txt", len(content), sum),
			fmt.Sprintf("sftp mkdir %q", remote+"/d"),
			fmt.Sprintf("sftp upload %q (%d bytes, sha256 %s)", remote+"/via-scp.txt", len(content), sum),
			fmt.Sprintf("scp upload to %q", remote+"/via-legacy.txt"),
			fmt.Sprintf("scp upload \"report.txt\" into %q (%d bytes, sha256 %s)", remote+"/via-legacy.txt", len(content), sum),
			fmt.Sprintf("scp download from %q", remote+"/via-legacy.txt"),
			fmt.Sprintf("scp download \"via-legacy.txt\" from %q (%d bytes, sha256 %s)", remote+"/via-legacy.txt", len(content), sum),
		} {
			if !strings.Contains(all, want) {
				t.Fatalf("the recording lacks %q:\n%s", want, all)
			}
		}
		if !strings.Contains(all, "sftp rename") {
			t.Fatalf("the rename is not in the recording:\n%s", all)
		}
	})
}

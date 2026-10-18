// This file extends the process harness defined in ssh_flow_test.go
// (buildBinary, startService, repoRoot, httpVaultClient, httpAuditEmitter)
// to prove the FULL flow — control plane and data plane together — across
// five real, independently running processes: Authorization, Session
// Broker, Password Vault, Audit Service, and ssh-proxy. Unlike the
// earlier version of this test (see NOTES_SANDBOX.md), the Session
// Broker is no longer simulated past CreateSession — its real
// POST /sessions/{id}/connect is called, which itself calls the real
// ssh-proxy over HTTP, which itself is then connected to by a real
// ssh.Client, reaching a real fake target SSH server. Nothing here is a
// stand-in for the Broker-to-Proxy link anymore.
package integration_test

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startServiceWithExtraPort starts a binary that listens on two ports —
// ssh-proxy's HTTP internal API (httpPort, health-checked like any other
// service) plus its real SSH listener (sshPort, passed via SSH_PORT).
func startServiceWithExtraPort(t *testing.T, root, binPath, httpPort, sshPort string, extraEnv ...string) *runningService {
	t.Helper()
	env := append([]string{"SSH_PORT=" + sshPort}, extraEnv...)
	return startService(t, root, binPath, httpPort, env...)
}

// authzCreatePolicy calls POST /policies directly against a running
// Authorization process. actorRoles is almost always []string{"platform-admin"}
// in these tests — the role cmd/authorization/main.go's BootstrapAdminPolicy
// grants authz:policy-admin to on first boot (BOOTSTRAP_ADMIN_ROLE default),
// since every Authorization process here is started fresh with an empty
// store. See admin_routes_test.go for the one test that also exercises a
// non-bootstrap role creating a policy through the Gateway.
func authzCreatePolicy(t *testing.T, baseURL string, actorRoles []string, role, resourcePattern, effect string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name": "it-test-policy", "role": role, "resourcePattern": resourcePattern,
		"effect": effect, "createdBy": "it-admin", "actorRoles": actorRoles,
	})
	resp, err := http.Post(baseURL+"/authz/v1/policies", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create-policy: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create-policy: status %d", resp.StatusCode)
	}
}

type brokerSession struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func brokerCreateSession(t *testing.T, baseURL string, actorRoles []string, accountID string) (*brokerSession, int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"requestedBy": "it-user1", "actorRoles": actorRoles, "targetAccountId": accountID,
		"protocol": "ssh", "justification": "integration test", "durationMinutes": 60,
	})
	resp, err := http.Post(baseURL+"/sessions", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("create-session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return nil, resp.StatusCode
	}
	var sess brokerSession
	if err := json.NewDecoder(resp.Body).Decode(&sess); err != nil {
		t.Fatalf("decode session response: %v", err)
	}
	return &sess, resp.StatusCode
}

func brokerConnect(t *testing.T, baseURL, sessionID string) (proxyEndpoint, ticket string, status int) {
	t.Helper()
	resp, err := http.Post(baseURL+"/sessions/"+sessionID+"/connect", "application/json", nil)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", resp.StatusCode
	}
	var out struct {
		ProxyEndpoint string `json:"proxyEndpoint"`
		Ticket        string `json:"ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode connect response: %v", err)
	}
	return out.ProxyEndpoint, out.Ticket, resp.StatusCode
}

func brokerTerminateSession(t *testing.T, baseURL, sessionID string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/sessions/"+sessionID, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("terminate-session: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// startFakeTargetSSHServer is a minimal real SSH server standing in for a
// privileged account's target host. It validates the presented password
// EXACTLY matches expectedPassword — proof that whatever credential
// reaches it is the genuine one fetched from the real Vault, not a stand-
// in — and echoes back whatever line it receives on a shell session.
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

func TestFullFlow_AuthorizationBrokerVaultAuditSSHProxy_AcrossFiveRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-3")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-3")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-2")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-2")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy")

	vault := startService(t, root, vaultBin, "18101", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18103")
	audit := startService(t, root, auditBin, "18102")
	authz := startService(t, root, authzBin, "18103")
	sshProxy := startServiceWithExtraPort(t, root, sshProxyBin, "18105", "18106",
		"VAULT_URL=http://127.0.0.1:18101",
		"AUDIT_URL=http://127.0.0.1:18102",
		"PROXY_SERVICE_ID=ssh-proxy",
		// This test is about authorization and the relay, not recording, and
		// runs no Command Recorder: opt out of the default (required) policy
		// explicitly — without RECORDER_URL the proxy refuses to start.
		"RECORDING_POLICY=best-effort",
	)
	broker := startService(t, root, brokerBin, "18104",
		"AUTHORIZATION_URL=http://127.0.0.1:18103",
		"VAULT_URL=http://127.0.0.1:18101",
		"AUDIT_URL=http://127.0.0.1:18102",
		"SSH_PROXY_URL=http://127.0.0.1:18105",
	)

	t.Logf("ssh-proxy internal API up at %s, SSH listener on :18106", sshProxy.baseURL)

	const secretValue = "full-flow-it-secret-99"
	targetAddr := startFakeTargetSSHServer(t, secretValue)

	const accountID = "acc_fullflow_it"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "fullflow-test-account", "root", targetAddr, secretValue, []string{"vault-admin"})

	t.Run("deny-by-default: no policy means CreateSession is refused", func(t *testing.T) {
		_, status := brokerCreateSession(t, broker.baseURL, []string{"dba"}, accountID)
		if status != http.StatusForbidden {
			t.Fatalf("expected 403 with no policy configured, got %d", status)
		}
	})

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")

	sess, status := brokerCreateSession(t, broker.baseURL, []string{"dba"}, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create-session: status %d", status)
	}

	proxyEndpoint, ticket, status := brokerConnect(t, broker.baseURL, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("connect: status %d", status)
	}
	if ticket == "" {
		t.Fatal("expected a non-empty connection ticket")
	}
	t.Logf("real ProxyControl.EstablishSession, via the Broker, returned proxyEndpoint=%q", proxyEndpoint)

	// -- the operator: a real ssh.Client, authenticating with the ticket --
	// obtained through the Broker's real public API — nothing simulated
	// from here on.
	clientConfig := &ssh.ClientConfig{
		User:            "operator",
		Auth:            []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	}
	client, err := ssh.Dial("tcp", "127.0.0.1:18106", clientConfig)
	if err != nil {
		t.Fatalf("client dial to ssh-proxy: %v", err)
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
	if _, err := fmt.Fprintf(stdin, "whoami-through-full-stack\n"); err != nil {
		t.Fatalf("write command: %v", err)
	}

	reader := bufio.NewReader(stdout)
	deadline := time.Now().Add(5 * time.Second)
	var line string
	for time.Now().Before(deadline) {
		line, err = reader.ReadString('\n')
		if err == nil && strings.Contains(line, "echo:whoami-through-full-stack") {
			break
		}
	}
	if !strings.Contains(line, "echo:whoami-through-full-stack") {
		t.Fatalf("expected the command to reach the real target through Authorization -> Broker -> Vault -> ssh-proxy and back, got %q (err=%v)", line, err)
	}
	client.Close()

	t.Run("audit chain is intact after the full five-process flow", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatalf("verify-chain: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: status %d", resp.StatusCode)
		}
	})

	t.Run("terminated session can no longer connect", func(t *testing.T) {
		if status := brokerTerminateSession(t, broker.baseURL, sess.ID); status != http.StatusOK {
			t.Fatalf("terminate-session: status %d", status)
		}
		if _, _, status := brokerConnect(t, broker.baseURL, sess.ID); status == http.StatusOK {
			t.Fatal("expected connect to fail for a terminated session")
		}
	})
}

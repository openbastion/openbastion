// This file proves the Command Recorder end to end, across EIGHT real,
// independently running processes: Authentication, Authorization, Session
// Broker, Password Vault, Audit Service, ssh-proxy, Command Recorder and
// the API Gateway. An operator logs in, gets a real SSH session through the
// proxy, types commands the way a real terminal does (Enter is '\r', and a
// sudo password is typed at a prompt), and an auditor then reads the
// session's text recording back through the Gateway.
//
// What it exists to catch, beyond each piece working alone: the proxy's
// asynchronous delivery really reaches the recorder; the recording is
// attributed to the right session; a secret typed at a prompt is stored
// nowhere; and the read side enforces RBAC without leaking which sessions
// exist.
package integration_test

import (
	"bufio"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

// startInteractiveTargetSSHServer is a real SSH server that behaves like a
// terminal rather than a line echoer: it ends a line on '\r' (what a PTY's
// ICRNL does), echoes what is typed, and plays a real sudo — a prompt with
// no trailing newline, then a line read with echo OFF.
const sudoPassword = "correct-sudo-pw"

func startInteractiveTargetSSHServer(t *testing.T, expectedPassword string) (addr string) {
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

	serve := func(ch ssh.Channel) {
		defer ch.Close()
		in := bufio.NewReader(ch)
		readLine := func(echo bool) (string, error) {
			var line []byte
			for {
				b, err := in.ReadByte()
				if err != nil {
					return "", err
				}
				if b == '\r' || b == '\n' {
					fmt.Fprint(ch, "\r\n")
					return string(line), nil
				}
				line = append(line, b)
				if echo {
					_, _ = ch.Write([]byte{b})
				}
			}
		}
		for {
			fmt.Fprint(ch, "$ ")
			line, err := readLine(true)
			if err != nil {
				return
			}
			if line == "sudo -s" {
				fmt.Fprint(ch, "[sudo] password for root: ")
				pw, err := readLine(false)
				if err != nil {
					return
				}
				if pw == sudoPassword {
					fmt.Fprint(ch, "root-shell-ready\r\n")
				} else {
					fmt.Fprint(ch, "Sorry, try again.\r\n")
				}
				continue
			}
			fmt.Fprintf(ch, "out:%s\r\n", line)
		}
	}

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
							ok := req.Type == "shell" || req.Type == "pty-req"
							if req.WantReply {
								_ = req.Reply(ok, nil)
							}
						}
					}()
					go serve(ch)
				}
			}()
		}
	}()
	return ln.Addr().String()
}

type recordingPage struct {
	SessionID string `json:"sessionId"`
	Entries   []struct {
		Timestamp time.Time `json:"timestamp"`
		Command   string    `json:"command"`
	} `json:"entries"`
	Page         int `json:"page"`
	PageSize     int `json:"pageSize"`
	TotalEntries int `json:"totalEntries"`
}

func (p recordingPage) commands() []string {
	out := make([]string, 0, len(p.Entries))
	for _, e := range p.Entries {
		out = append(out, e.Command)
	}
	return out
}

// gatewayGetRecording calls GET /sessions/{id}/recording through the Gateway.
func gatewayGetRecording(t *testing.T, baseURL, token, sessionID, query string) (status int, raw []byte, page recordingPage) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/sessions/"+sessionID+"/recording"+query, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("get recording: %v", err)
	}
	defer resp.Body.Close()
	raw, _ = io.ReadAll(resp.Body)
	if resp.StatusCode == http.StatusOK {
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatalf("decode recording: %v (%s)", err, raw)
		}
	}
	return resp.StatusCode, raw, page
}

func TestRecordingFlow_InteractiveSessionIsRecordedAndReadableByAnAuditor_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-5")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-5")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-5")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-5")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-5")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-5")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-5")

	vault := startService(t, root, vaultBin, "18501", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18503")
	startService(t, root, auditBin, "18502")
	authz := startService(t, root, authzBin, "18503")
	authn := startService(t, root, authnBin, "18507", "SKIP_DEMO_SEED=1")
	startService(t, root, recorderBin, "18509", "AUTHORIZATION_URL=http://127.0.0.1:18503")
	startServiceWithExtraPort(t, root, sshProxyBin, "18505", "18506",
		"VAULT_URL=http://127.0.0.1:18501",
		"AUDIT_URL=http://127.0.0.1:18502",
		"PROXY_SERVICE_ID=ssh-proxy",
		"RECORDER_URL=http://127.0.0.1:18509",
	)
	broker := startService(t, root, brokerBin, "18504",
		"AUTHORIZATION_URL=http://127.0.0.1:18503",
		"VAULT_URL=http://127.0.0.1:18501",
		"AUDIT_URL=http://127.0.0.1:18502",
		"SSH_PROXY_URL=http://127.0.0.1:18505",
	)
	gateway := startService(t, root, gatewayBin, "18508",
		"AUTHENTICATION_URL=http://127.0.0.1:18507",
		"SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18509",
	)

	const targetSecret = "recording-it-target-secret"
	targetAddr := startInteractiveTargetSSHServer(t, targetSecret)

	const accountID = "acc_recording_it"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "recording-test-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	authCreateUser(t, authn.baseURL, "auditor", "Auditor", "aud-password-123", []string{"session-auditor"})

	operatorToken, status := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")
	if status != http.StatusOK {
		t.Fatalf("operator login: status %d", status)
	}
	auditorToken, status := gatewayLogin(t, gateway.baseURL, "auditor", "aud-password-123")
	if status != http.StatusOK {
		t.Fatalf("auditor login: status %d", status)
	}

	sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create session: status %d", status)
	}
	_, ticket, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("connect: status %d", status)
	}

	// -- the operator, on a real terminal-like SSH session ------------------
	client, err := ssh.Dial("tcp", "127.0.0.1:18506", &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial ssh-proxy: %v", err)
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
		outMu.Lock()
		defer outMu.Unlock()
		t.Fatalf("never saw %q from the target; output so far: %q", want, outBuf.String())
	}

	// Enter is '\r', as in a real terminal.
	fmt.Fprint(stdin, "whoami\r")
	waitFor("out:whoami")
	fmt.Fprint(stdin, "sudo -s\r")
	waitFor("[sudo] password for root: ")
	fmt.Fprint(stdin, sudoPassword+"\r")
	waitFor("root-shell-ready")
	fmt.Fprint(stdin, "id\r")
	waitFor("out:id")
	client.Close()

	// -- the auditor reads the recording back, through the Gateway ----------
	// Delivery from the proxy is asynchronous, so wait for it to arrive.
	var raw []byte
	var page recordingPage
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		status, raw, page = gatewayGetRecording(t, gateway.baseURL, auditorToken, sess.ID, "")
		if status == http.StatusOK && page.TotalEntries >= 4 {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if status != http.StatusOK {
		t.Fatalf("auditor read: status %d: %s", status, raw)
	}

	t.Run("the recording holds each command, in order, for the right session", func(t *testing.T) {
		want := []string{"whoami", "sudo -s", "[redacted: input at a secret prompt]", "id"}
		got := page.commands()
		if page.SessionID != sess.ID || page.TotalEntries != 4 || len(got) != 4 {
			t.Fatalf("session=%q total=%d commands=%q", page.SessionID, page.TotalEntries, got)
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("want %q, got %q", want, got)
			}
		}
		for i, e := range page.Entries {
			if e.Timestamp.IsZero() || (i > 0 && e.Timestamp.Before(page.Entries[i-1].Timestamp)) {
				t.Fatalf("timestamps must be set and non-decreasing: %+v", page.Entries)
			}
		}
		if page.Page != 1 || page.PageSize != 20 {
			t.Fatalf("expected the served page 1 / size 20 to be reported, got %d / %d", page.Page, page.PageSize)
		}
	})

	t.Run("the sudo password is stored nowhere in the recording", func(t *testing.T) {
		if strings.Contains(string(raw), sudoPassword) {
			t.Fatalf("the secret typed at the sudo prompt is in the recording: %s", raw)
		}
		if strings.Contains(string(raw), targetSecret) {
			t.Fatalf("the target credential is in the recording: %s", raw)
		}
	})

	t.Run("pagination serves the requested slice with the real total", func(t *testing.T) {
		status, _, p := gatewayGetRecording(t, gateway.baseURL, auditorToken, sess.ID, "?page=2&pageSize=2")
		if status != http.StatusOK || p.Page != 2 || p.PageSize != 2 || p.TotalEntries != 4 {
			t.Fatalf("status=%d page=%d size=%d total=%d", status, p.Page, p.PageSize, p.TotalEntries)
		}
		if got := p.commands(); len(got) != 2 || got[0] != "[redacted: input at a secret prompt]" || got[1] != "id" {
			t.Fatalf("page 2 of size 2: %q", got)
		}
	})

	t.Run("an operator without the auditor role cannot read the recording", func(t *testing.T) {
		status, raw, _ := gatewayGetRecording(t, gateway.baseURL, operatorToken, sess.ID, "")
		if status != http.StatusForbidden {
			t.Fatalf("expected 403, got %d: %s", status, raw)
		}
		if strings.Contains(string(raw), "whoami") {
			t.Fatalf("a denied response leaked recording content: %s", raw)
		}
	})

	t.Run("a denial is the same whether or not the session exists", func(t *testing.T) {
		existing, _, _ := gatewayGetRecording(t, gateway.baseURL, operatorToken, sess.ID, "")
		missing, _, _ := gatewayGetRecording(t, gateway.baseURL, operatorToken, "no-such-session", "")
		if existing != http.StatusForbidden || missing != http.StatusForbidden {
			t.Fatalf("expected 403 for both, got %d (exists) and %d (missing)", existing, missing)
		}
	})

	t.Run("an auditor reading a session with no recording gets an empty one, not a 404", func(t *testing.T) {
		status, raw, p := gatewayGetRecording(t, gateway.baseURL, auditorToken, "no-such-session", "")
		if status != http.StatusOK || p.TotalEntries != 0 || len(p.Entries) != 0 {
			t.Fatalf("status=%d total=%d: %s", status, p.TotalEntries, raw)
		}
	})

	t.Run("reading a recording requires a token", func(t *testing.T) {
		if status, _, _ := gatewayGetRecording(t, gateway.baseURL, "", sess.ID, ""); status != http.StatusUnauthorized {
			t.Fatalf("expected 401 without a token, got %d", status)
		}
	})

	t.Run("a client-supplied actorRoles cannot grant read access", func(t *testing.T) {
		status, _, _ := gatewayGetRecording(t, gateway.baseURL, operatorToken, sess.ID, "?actorRoles=session-auditor")
		if status != http.StatusForbidden {
			t.Fatalf("expected 403 despite a forged actorRoles parameter, got %d", status)
		}
	})
}

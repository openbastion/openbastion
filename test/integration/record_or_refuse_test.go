// Record-or-refuse (ADR-0008), proved across EIGHT real processes: Authentication,
// Authorization, Session Broker, Password Vault, Audit Service, ssh-proxy,
// Command Recorder and the API Gateway — plus a pass-through in front of the
// Audit Service that records what the proxy emits, because the Audit Service
// itself has no read endpoint yet.
//
// The recorder is killed and restarted under a live deployment, and the
// operator's side of it is observed from the outside: what the SSH client sees,
// what the Gateway answers, and — the point — what the TARGET actually
// received. The claim under test is a negative one (an unrecorded command is
// never executed), so the target reports every line it gets.
package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func newLocalServer(t *testing.T, h http.Handler) string {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	return srv.URL
}

// runUntilExit runs a binary that is expected to refuse to start, and returns
// its output. A process that is still running after a few seconds is a failure:
// the refusal is supposed to be immediate, not a server that came up anyway.
func runUntilExit(t *testing.T, root, bin string, env ...string) string {
	t.Helper()
	cmd := exec.Command(bin)
	cmd.Env = append(buildEnv(root), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatalf("expected a non-zero exit, got success; output:\n%s", out.String())
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the process was still running after 5s — it must refuse to start; output so far:\n%s", out.String())
	}
	return out.String()
}

// auditSpy forwards everything to the real Audit Service and remembers the
// events that went through it.
type auditSpy struct {
	baseURL string
	mu      sync.Mutex
	events  []spiedEvent
	// down makes the spy answer 503 to every emit-event, without forwarding it and without
	// remembering it: the Audit Service, for whoever asks, is not there.
	down bool
}

func (s *auditSpy) setDown(down bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.down = down
}

func (s *auditSpy) isDown() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.down
}

type spiedEvent struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
}

func startAuditSpy(t *testing.T, upstream string) *auditSpy {
	t.Helper()
	target, err := url.Parse(upstream)
	if err != nil {
		t.Fatal(err)
	}
	spy := &auditSpy{}
	proxy := httputil.NewSingleHostReverseProxy(target)
	srv := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/emit-event") {
			if spy.isDown() {
				http.Error(w, "audit down (the spy says so)", http.StatusServiceUnavailable)
				return
			}
			body, _ := io.ReadAll(r.Body)
			r.Body = io.NopCloser(bytes.NewReader(body))
			var ev spiedEvent
			if json.Unmarshal(body, &ev) == nil {
				spy.mu.Lock()
				spy.events = append(spy.events, ev)
				spy.mu.Unlock()
			}
		}
		proxy.ServeHTTP(w, r)
	}))
	spy.baseURL = srv
	return spy
}

func (s *auditSpy) has(action, sessionID string, success bool) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Action == action && e.ResourceID == sessionID && e.Success == success {
			return true
		}
	}
	return false
}

func (s *auditSpy) waitFor(t *testing.T, action, sessionID string, success bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.has(action, sessionID, success) {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	t.Fatalf("audit event %s (session %s, success=%v) never reached the Audit Service; saw %+v", action, sessionID, success, s.events)
}

func (s *auditSpy) count(action, sessionID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Action == action && e.ResourceID == sessionID {
			n++
		}
	}
	return n
}

// shell is an operator on a real SSH session through the proxy.
type shell struct {
	t      *testing.T
	stdin  io.Writer
	mu     sync.Mutex
	out    strings.Builder
	closed chan struct{}
}

func openShell(t *testing.T, proxyAddr, ticket string) *shell {
	t.Helper()
	client, err := ssh.Dial("tcp", proxyAddr, &ssh.ClientConfig{
		User: "operator", Auth: []ssh.AuthMethod{ssh.Password(ticket)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
	})
	if err != nil {
		t.Fatalf("dial ssh-proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	session, err := client.NewSession()
	if err != nil {
		t.Fatalf("client session: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	if err := session.RequestPty("xterm", 80, 40, ssh.TerminalModes{}); err != nil {
		t.Fatalf("client pty: %v", err)
	}
	stdin, _ := session.StdinPipe()
	stdout, _ := session.StdoutPipe()
	if err := session.Shell(); err != nil {
		t.Fatalf("client shell: %v", err)
	}
	sh := &shell{t: t, stdin: stdin, closed: make(chan struct{})}
	go func() {
		defer close(sh.closed)
		buf := make([]byte, 256)
		for {
			n, err := stdout.Read(buf)
			if n > 0 {
				sh.mu.Lock()
				sh.out.Write(buf[:n])
				sh.mu.Unlock()
			}
			if err != nil {
				return
			}
		}
	}()
	return sh
}

func (s *shell) output() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.out.String()
}

func (s *shell) waitFor(want string) {
	s.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(s.output(), want) {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	s.t.Fatalf("never saw %q; output so far: %q", want, s.output())
}

func (s *shell) waitClosed() {
	s.t.Helper()
	select {
	case <-s.closed:
	case <-time.After(8 * time.Second):
		s.t.Fatalf("the session was not ended; output so far: %q", s.output())
	}
}

// gatewayConnectRaw is gatewayConnect, keeping the status and body whatever they are.
func gatewayConnectRaw(t *testing.T, baseURL, token, sessionID string) (status int, body string, ticket string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions/"+sessionID+"/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway connect: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out struct {
		Ticket string `json:"ticket"`
	}
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, string(raw), out.Ticket
}

func TestRecordOrRefuse_ARecorderOutageRefusesAndEndsSessions_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-6")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-6")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-6")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-6")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-6")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-6")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-6")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-6")

	vault := startService(t, root, vaultBin, "18601", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18603")
	audit := startService(t, root, auditBin, "18602")
	authz := startService(t, root, authzBin, "18603")
	authn := startService(t, root, authnBin, "18607", "SKIP_DEMO_SEED=1")
	recorder := startService(t, root, recorderBin, "18609", "AUTHORIZATION_URL=http://127.0.0.1:18603")
	spy := startAuditSpy(t, audit.baseURL)
	startServiceWithExtraPort(t, root, sshProxyBin, "18605", "18606",
		"VAULT_URL=http://127.0.0.1:18601",
		"AUDIT_URL="+spy.baseURL, // the proxy's events pass through the spy to the real Audit Service
		"PROXY_SERVICE_ID=ssh-proxy",
		"RECORDER_URL=http://127.0.0.1:18609",
		"RECORDING_POLICY=required",
	)
	broker := startService(t, root, brokerBin, "18604",
		"AUTHORIZATION_URL=http://127.0.0.1:18603",
		"VAULT_URL=http://127.0.0.1:18601",
		"AUDIT_URL=http://127.0.0.1:18602",
		"SSH_PROXY_URL=http://127.0.0.1:18605",
	)
	gateway := startService(t, root, gatewayBin, "18608",
		"AUTHENTICATION_URL=http://127.0.0.1:18607",
		"SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18609",
	)

	// The target reports every line it receives.
	const targetSecret = "record-or-refuse-target-secret"
	var (
		targetMu    sync.Mutex
		targetLines []string
	)
	targetSaw := func() []string {
		targetMu.Lock()
		defer targetMu.Unlock()
		return append([]string(nil), targetLines...)
	}
	targetAddr := startObservedInteractiveTargetSSHServer(t, targetSecret, func(line string) {
		targetMu.Lock()
		defer targetMu.Unlock()
		targetLines = append(targetLines, line)
	})

	const accountID = "acc_record_or_refuse"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "record-or-refuse-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
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

	newSession := func() *brokerSession {
		t.Helper()
		sess, status := gatewayCreateSession(t, gateway.baseURL, operatorToken, "", nil, accountID)
		if status != http.StatusCreated {
			t.Fatalf("create session: status %d", status)
		}
		return sess
	}
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen

	// ---- 1. a recorder outage in the middle of a session ------------------------------
	sess1 := newSession()
	_, ticket1, status := gatewayConnect(t, gateway.baseURL, operatorToken, sess1.ID)
	if status != http.StatusOK {
		t.Fatalf("connect: status %d", status)
	}
	sh1 := openShell(t, "127.0.0.1:18606", ticket1)

	fmt.Fprint(sh1.stdin, "whoami\r")
	sh1.waitFor("out:whoami")

	stopService(t, recorder) // the outage

	// Typing still echoes; only SUBMITTING a command needs the recorder.
	fmt.Fprint(sh1.stdin, "cat /etc/shadow\r")
	sh1.waitClosed()
	settle()

	t.Run("the command typed after the outage was never executed on the target", func(t *testing.T) {
		for _, line := range targetSaw() {
			if strings.Contains(line, "shadow") {
				t.Fatalf("an unrecorded command reached the target: %q", targetSaw())
			}
		}
		if strings.Contains(sh1.output(), "out:cat /etc/shadow") {
			t.Fatalf("the target executed it: %q", sh1.output())
		}
	})
	t.Run("the operator is told why the session ended", func(t *testing.T) {
		if !strings.Contains(sh1.output(), "recording is unavailable") {
			t.Fatalf("no explanation in %q", sh1.output())
		}
		if strings.Contains(sh1.output(), "127.0.0.1:18609") || strings.Contains(sh1.output(), "connection refused") {
			t.Fatalf("the message leaks the recorder's address or error: %q", sh1.output())
		}
	})
	t.Run("the audit trail records the loss and the abnormal end", func(t *testing.T) {
		spy.waitFor(t, "session.recording_lost", sess1.ID, false)
		spy.waitFor(t, "session.terminate", sess1.ID, false)
	})

	// ---- 2. connecting while the recorder is down -------------------------------------
	sess2 := newSession()
	t.Run("connect is refused with a 503, and says so", func(t *testing.T) {
		status, body, ticket := gatewayConnectRaw(t, gateway.baseURL, operatorToken, sess2.ID)
		if status != http.StatusServiceUnavailable {
			t.Fatalf("expected 503 while the recorder is down, got %d: %s", status, body)
		}
		if ticket != "" {
			t.Fatal("a ticket was issued for a session that cannot be recorded")
		}
		if !strings.Contains(body, "recording unavailable") {
			t.Fatalf("the refusal does not say why: %s", body)
		}
		if strings.Contains(body, "18609") || strings.Contains(body, "connection refused") {
			t.Fatalf("the refusal leaks the recorder's address: %s", body)
		}
		spy.waitFor(t, "session.recording_unavailable", sess2.ID, false)
	})

	// ---- 3. a ticket obtained while healthy, redeemed after the recorder fails --------
	// Bring the recorder back, get a ticket, lose the recorder again, THEN connect.
	recorder = startService(t, root, recorderBin, "18609", "AUTHORIZATION_URL=http://127.0.0.1:18603")
	sess3 := newSession()
	status, body, ticket3 := gatewayConnectRaw(t, gateway.baseURL, operatorToken, sess3.ID)
	if status != http.StatusOK {
		t.Fatalf("connect with a healthy recorder: status %d: %s", status, body)
	}
	stopService(t, recorder)

	sh3 := openShell(t, "127.0.0.1:18606", ticket3)
	sh3.waitClosed()
	settle()
	t.Run("a session whose recorder failed after the ticket was issued is refused at the door", func(t *testing.T) {
		if !strings.Contains(sh3.output(), "recording is unavailable") {
			t.Fatalf("no explanation in %q", sh3.output())
		}
		spy.waitFor(t, "session.recording_unavailable", sess3.ID, false)
		if n := spy.count("session.terminate", sess3.ID); n != 0 {
			t.Fatalf("a refused session was reported as having run and ended (%d session.terminate events)", n)
		}
		if lines := targetSaw(); len(lines) != 1 || lines[0] != "whoami" {
			t.Fatalf("the refused session reached the target: %q", lines)
		}
	})

	// ---- 4. recovery: the same session connects once the recorder is back -------------
	recorder = startService(t, root, recorderBin, "18609", "AUTHORIZATION_URL=http://127.0.0.1:18603")
	t.Run("once the recorder is back the same session connects, runs and is recorded", func(t *testing.T) {
		status, body, ticket := gatewayConnectRaw(t, gateway.baseURL, operatorToken, sess3.ID)
		if status != http.StatusOK {
			t.Fatalf("reconnect after recovery: status %d: %s", status, body)
		}
		sh := openShell(t, "127.0.0.1:18606", ticket)
		fmt.Fprint(sh.stdin, "uptime\r")
		sh.waitFor("out:uptime")

		// Acknowledged before it ran, so it is readable right away.
		status, raw, page := gatewayGetRecording(t, gateway.baseURL, auditorToken, sess3.ID, "")
		if status != http.StatusOK || len(page.commands()) != 1 || page.commands()[0] != "uptime" {
			t.Fatalf("the recovered session was not recorded: status %d, %s", status, raw)
		}
	})

	t.Run("the audit chain is intact after all of it", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatalf("verify-chain: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: status %d", resp.StatusCode)
		}
	})
}

// A proxy told to record, with nothing to record to, refuses to start — it does
// not come up and quietly accept sessions. Run on the real binary, without any
// other service: the check happens before the proxy touches the network.
func TestSSHProxyMain_RefusesToStartWithoutARecorderUnlessBestEffortIsAskedFor(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-policy-check")

	t.Run("the default (required) without RECORDER_URL", func(t *testing.T) {
		out := runUntilExit(t, root, bin, "PORT=18697", "SSH_PORT=18696")
		if !strings.Contains(out, "RECORDER_URL") || !strings.Contains(out, "refusing to start") {
			t.Fatalf("expected a refusal naming RECORDER_URL, got:\n%s", out)
		}
	})
	t.Run("an explicit required without RECORDER_URL", func(t *testing.T) {
		out := runUntilExit(t, root, bin, "PORT=18697", "SSH_PORT=18696", "RECORDING_POLICY=required")
		if !strings.Contains(out, "refusing to start") {
			t.Fatalf("expected a refusal, got:\n%s", out)
		}
	})
	t.Run("a policy value it does not know is an error, not the weak mode", func(t *testing.T) {
		out := runUntilExit(t, root, bin, "PORT=18697", "SSH_PORT=18696", "RECORDING_POLICY=Best-Effort", "RECORDER_URL=http://127.0.0.1:1")
		if !strings.Contains(out, "RECORDING_POLICY") {
			t.Fatalf("expected the error to name RECORDING_POLICY, got:\n%s", out)
		}
	})
}

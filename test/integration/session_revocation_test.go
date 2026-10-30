// Ending a session cuts it at the proxy (ADR-0018), on real processes: Audit, Authorization,
// Authentication, the Vault, the Command Recorder, the SSH proxy, the Session Broker and the
// API Gateway, with a real SSH client and a real target.
//
// Before ADR-0018 ending a session changed the Broker's record and nothing else. The proxy had
// one internal route, establish-session, and no way to be told that a session was over: an SSH
// connection already open ran on until its ticket expired — the end of the session — and a
// ticket already issued but not yet used opened a connection long after.
//
// The claims that matter: a session ended by its requester or by an authority has its open
// connections cut, all of them, and its unused tickets refused; the other sessions of the same
// person are not touched; a termination somebody was refused cuts nothing; when the proxy
// cannot be told, nothing is ended and the caller is told so — and the same call works once
// the proxy is back; what the operator types after the cut never reaches the target; and a
// session the proxy was told to cut cannot be established again, so a connect that was in
// flight when the session ended does not leave a ticket behind.
package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestSessionRevocation_EndingASessionCutsItAtTheProxy_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-18")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-18")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-18")
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-18")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-18")
	proxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-18")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-18")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-18")

	audit := startService(t, root, auditBin, "18901")
	authz := startService(t, root, authzBin, "18902")
	authn := startService(t, root, authnBin, "18903", "SKIP_DEMO_SEED=1")
	vault := startService(t, root, vaultBin, "18904", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL)
	recorder := startService(t, root, recorderBin, "18905", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	spy := startAuditSpy(t, audit.baseURL)
	proxyEnv := []string{
		"VAULT_URL=" + vault.baseURL, "AUDIT_URL=" + spy.baseURL, "PROXY_SERVICE_ID=ssh-proxy",
		"RECORDER_URL=" + recorder.baseURL, "RECORDING_POLICY=required",
	}
	proxy := startServiceWithExtraPort(t, root, proxyBin, "18906", "18907", proxyEnv...)
	broker := startService(t, root, brokerBin, "18908",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL, "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18906")
	gw := startService(t, root, gatewayBin, "18909",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL="+recorder.baseURL, "SESSION_ACTION_BURST=100", "SESSION_ACTION_RATE_PER_MINUTE=600")
	const proxySSH = "127.0.0.1:18907"
	parent := t

	// The target reports every line it receives.
	const targetSecret = "revocation-target-secret"
	var (
		targetMu    sync.Mutex
		targetLines []string
	)
	targetSaw := func(line string) bool {
		targetMu.Lock()
		defer targetMu.Unlock()
		for _, l := range targetLines {
			if l == line {
				return true
			}
		}
		return false
	}
	targetAddr := startObservedInteractiveTargetSSHServer(t, targetSecret, func(line string) {
		targetMu.Lock()
		defer targetMu.Unlock()
		targetLines = append(targetLines, line)
	})

	const accountID = "acc_revocation"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "revocation-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"intern"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	operator, bob := login("operator", "op-password-123"), login("bob", "bob-password-12345")

	open := func(t *testing.T) string {
		t.Helper()
		sess, status := gatewayCreateSession(t, gw.baseURL, operator, "", nil, accountID)
		if status != http.StatusCreated || sess == nil || sess.Status != "active" {
			t.Fatalf("session: %d %+v", status, sess)
		}
		return sess.ID
	}
	ticket := func(t *testing.T, id string) string {
		t.Helper()
		_, tk, status := gatewayConnect(t, gw.baseURL, operator, id)
		if status != http.StatusOK || tk == "" {
			t.Fatalf("connect: %d", status)
		}
		return tk
	}
	end := func(token, id string) (int, string) {
		code, _, text := rawRequest(t, http.MethodDelete, gw.baseURL+"/sessions/"+id, token, "")
		return code, text
	}
	statusOf := func(t *testing.T, id string) string {
		t.Helper()
		s, _ := gatewayGetSession(t, gw.baseURL, operator, id)["status"].(string)
		return s
	}
	// alive: the operator types a line and the target answers it, through the proxy.
	alive := func(t *testing.T, sh *shell, word string) {
		t.Helper()
		fmt.Fprint(sh.stdin, word+"\r")
		sh.waitFor("out:" + word)
	}
	// dialWith says whether a ticket still opens a connection through the proxy.
	dialWith := func(tk string) error {
		client, err := ssh.Dial("tcp", proxySSH, &ssh.ClientConfig{
			User: "operator", Auth: []ssh.AuthMethod{ssh.Password(tk)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second,
		})
		if err == nil {
			_ = client.Close()
		}
		return err
	}
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen

	// Session A: two live connections and one ticket nobody used. Session B: the same operator's
	// other session, which must not be touched by anything that happens to A.
	sessA, sessB := open(t), open(t)
	shA1, shA2 := openShell(t, proxySSH, ticket(t, sessA)), openShell(t, proxySSH, ticket(t, sessA))
	unusedA := ticket(t, sessA)
	shB := openShell(t, proxySSH, ticket(t, sessB))
	alive(t, shA1, "a1-before")
	alive(t, shA2, "a2-before")
	alive(t, shB, "b-before")

	t.Run("a termination somebody was refused cuts nothing", func(t *testing.T) {
		if code, text := end(bob, sessA); code != http.StatusForbidden {
			t.Fatalf("Bob: %d %s, want 403", code, text)
		}
		alive(t, shA1, "a1-after-refusal")
		alive(t, shA2, "a2-after-refusal")
	})

	t.Run("the requester ends the session: every open connection is cut and the unused ticket is dead", func(t *testing.T) {
		if code, text := end(operator, sessA); code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("the requester: %d %s, want 200 and terminated", code, text)
		}
		// By the time the answer came back the connections are being closed: a short wait
		// for the SSH client to notice, not for the proxy to decide.
		shA1.waitClosed()
		shA2.waitClosed()
		// The operator is told why, and not by whom.
		for name, sh := range map[string]*shell{"first": shA1, "second": shA2} {
			if out := sh.output(); !strings.Contains(out, "openbastion: session ended because it was terminated.\r\n") {
				t.Fatalf("the %s operator was not told, in exactly those words, that the session was terminated — it must not say who did it; output: %q", name, out)
			}
		}
		if err := dialWith(unusedA); err == nil {
			t.Fatal("a ticket issued before the termination opened a connection after it")
		}
		spy.waitFor(t, "session.revoked", sessA, true)
	})

	t.Run("what is typed after the cut never reaches the target", func(t *testing.T) {
		_, _ = fmt.Fprint(shA1.stdin, "typed-after-the-cut\r")
		settle()
		if targetSaw("typed-after-the-cut") {
			t.Fatal("the target received a line typed after the session was ended")
		}
	})

	t.Run("the other session of the same person is not touched", func(t *testing.T) {
		alive(t, shB, "b-after")
		if spy.has("session.revoked", sessB, true) {
			t.Fatal("a session nobody ended was reported as cut")
		}
		if got := statusOf(t, sessB); got != "active" {
			t.Fatalf("session B is %q, want active", got)
		}
	})

	t.Run("an ended session cannot be connected again", func(t *testing.T) {
		if _, tk, status := gatewayConnect(t, gw.baseURL, operator, sessA); status == http.StatusOK || tk != "" {
			t.Fatalf("connect on an ended session: %d with ticket %q, want a refusal", status, tk)
		}
	})

	t.Run("a session the proxy was told to cut cannot be established again: the connect that was in flight leaves no ticket", func(t *testing.T) {
		const inFlight = "session_in_flight_0001"
		code, _, text := rawRequest(t, http.MethodPost, proxy.baseURL+"/internal/v1/revoke-session", "", fmt.Sprintf(`{"session_id":%q,"ttl_seconds":60}`, inFlight))
		if code != http.StatusOK {
			t.Fatalf("revoke-session: %d %s, want 200", code, text)
		}
		establish := func(id string) int {
			code, _, _ := rawRequest(t, http.MethodPost, proxy.baseURL+"/internal/v1/establish-session", "",
				fmt.Sprintf(`{"session_id":%q,"target_host":%q,"target_user":"root","vault_scope_token":"x","ttl_seconds":60}`, id, targetAddr))
			return code
		}
		if got := establish(inFlight); got != http.StatusConflict {
			t.Fatalf("establish-session on a revoked session: %d, want 409", got)
		}
		if got := establish("session_never_revoked_0002"); got != http.StatusOK {
			t.Fatalf("establish-session on another session: %d, want 200 (the memory of a revocation is per session)", got)
		}
	})

	t.Run("when the proxy cannot be told, nothing is ended — and the same call works once it is back", func(t *testing.T) {
		sessD := open(t)
		stopService(t, proxy)
		code, text := end(operator, sessD)
		if code != http.StatusServiceUnavailable {
			t.Fatalf("with the proxy down: %d %s, want 503", code, text)
		}
		if strings.Contains(text, "127.0.0.1") || strings.Contains(text, "dial tcp") {
			t.Fatalf("the proxy's address reached the client: %q", text)
		}
		if got := statusOf(t, sessD); got != "active" {
			t.Fatalf("the session is %q after a termination that could not cut it, want active", got)
		}
		spy.waitFor(t, "session.terminate", sessD, false) // the attempt is on the record: it did not end the session
		if spy.has("session.terminate", sessD, true) {
			t.Fatal("a termination that could not be made was audited as a success")
		}

		// Started with the test's own t, not the subtest's: the process must outlive this subtest.
		proxy = startServiceWithExtraPort(parent, root, proxyBin, "18906", "18907", proxyEnv...)
		code, text = end(operator, sessD)
		if code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("with the proxy back: %d %s, want 200", code, text)
		}
		spy.waitFor(t, "session.terminate", sessD, true)
	})

	t.Run("the answer of the proxy is shaped: what is asked of it is checked", func(t *testing.T) {
		for name, body := range map[string]string{
			"no body":             ``,
			"not JSON":            `session_id=x`,
			"no session":          `{"ttl_seconds":60}`,
			"no time to remember": `{"session_id":"s"}`,
			"a negative time":     `{"session_id":"s","ttl_seconds":-1}`,
		} {
			if code, _, text := rawRequest(t, http.MethodPost, proxy.baseURL+"/internal/v1/revoke-session", "", body); code != http.StatusBadRequest {
				t.Fatalf("%s: %d %s, want 400", name, code, text)
			}
		}
		code, _, text := rawRequest(t, http.MethodGet, proxy.baseURL+"/internal/v1/revoke-session", "", "")
		if code != http.StatusMethodNotAllowed {
			t.Fatalf("GET: %d %s, want 405", code, text)
		}
		var out struct {
			TicketsRevoked int `json:"tickets_revoked"`
			ConnectionsCut int `json:"connections_cut"`
		}
		code, _, text = rawRequest(t, http.MethodPost, proxy.baseURL+"/internal/v1/revoke-session", "", `{"session_id":"session_nothing_here","ttl_seconds":30}`)
		if code != http.StatusOK || json.Unmarshal([]byte(text), &out) != nil || out.TicketsRevoked != 0 || out.ConnectionsCut != 0 {
			t.Fatalf("revoking a session the proxy knows nothing of: %d %s, want 200 and nothing cut", code, text)
		}
	})
}

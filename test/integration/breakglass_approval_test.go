// The double validation of break-glass (ADR-0011), proved across EIGHT real processes —
// with the Broker on its strict default: approval required, nobody told otherwise.
//
// The scenario is ADR-0009's emergency (the recorder is down, an on-call engineer needs a
// shell) with the second person added. The claims that matter are negative ones — nobody
// approves themself, a forged body decides nothing, the approver cannot use what he
// approved, a decision happens once — so the target reports every line it receives and the
// audit trail is read through a pass-through that remembers who emitted what.
package integration_test

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatewayDecide posts a decision on a request through the Gateway. body is sent as the
// client's own request body — which the Gateway is supposed to ignore.
func gatewayDecide(t *testing.T, baseURL, token, sessionID, action, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions/"+sessionID+"/"+action, strings.NewReader(body))
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway %s: %v", action, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func gatewayGetSession(t *testing.T, baseURL, token, sessionID string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/sessions/"+sessionID, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway get session: %v", err)
	}
	defer resp.Body.Close()
	var out map[string]any
	raw, _ := io.ReadAll(resp.Body)
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode session: %v (%s)", err, raw)
	}
	return out
}

// userIDOf reads the subject out of a JWT the Authentication Service issued, so that a test
// can say WHICH user an action must be attributed to — without trusting the Gateway's word.
func userIDOf(t *testing.T, token string) string {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("not a JWT: %q", token)
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode token payload: %v", err)
	}
	var claims struct {
		Sub string `json:"sub"`
	}
	if err := json.Unmarshal(raw, &claims); err != nil || claims.Sub == "" {
		t.Fatalf("no subject in the token: %s (%v)", raw, err)
	}
	return claims.Sub
}

// actorOf returns who emitted the first event of this action, session and outcome.
func (s *auditSpy) actorOf(action, sessionID string, success bool) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Action == action && e.ResourceID == sessionID && e.Success == success {
			return e.ActorID, true
		}
	}
	return "", false
}

func TestBreakGlassApproval_TwoPeopleForAnEmergencyAccess_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-8")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-8")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-8")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-8")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-8")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-8")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-8")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-8")

	vault := startService(t, root, vaultBin, "18711", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18713")
	audit := startService(t, root, auditBin, "18712")
	authz := startService(t, root, authzBin, "18713")
	authn := startService(t, root, authnBin, "18717", "SKIP_DEMO_SEED=1")
	recorder := startService(t, root, recorderBin, "18719", "AUTHORIZATION_URL=http://127.0.0.1:18713", "AUDIT_URL="+audit.baseURL)
	spy := startAuditSpy(t, audit.baseURL)

	startServiceWithExtraPort(t, root, sshProxyBin, "18715", "18716",
		"VAULT_URL=http://127.0.0.1:18711", "AUDIT_URL="+spy.baseURL, "PROXY_SERVICE_ID=ssh-proxy",
		"RECORDER_URL=http://127.0.0.1:18719", "RECORDING_POLICY=required", "BREAKGLASS_ENABLED=true")
	// BREAKGLASS_APPROVAL is not set: the strict default is what is under test.
	broker := startService(t, root, brokerBin, "18714",
		"AUTHORIZATION_URL=http://127.0.0.1:18713", "VAULT_URL=http://127.0.0.1:18711", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18715", "BREAKGLASS_MAX_MINUTES=30")
	gateway := startService(t, root, gatewayBin, "18718",
		"AUTHENTICATION_URL=http://127.0.0.1:18717", "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18719")

	const targetSecret = "approval-target-secret"
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

	const accountID = "acc_approval"
	const reason = "recorder down during P1 incident INC-4521"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "approval-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	// Three distinct authorities on the same account: to open a session, to ask for
	// break-glass, and to approve it. Nobody holds more than they were given.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "incident-lead", "breakglass-approve:account:"+accountID, "allow")
	authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "sre-second", "Second SRE", "second-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "lead-bob", "Incident lead", "bob-password-123", []string{"incident-lead"})
	authCreateUser(t, authn.baseURL, "dba-alice", "Alice (DBA)", "alice-password-1", []string{"dba"})
	// Carol holds BOTH authorities — the worst case for self-approval.
	authCreateUser(t, authn.baseURL, "sre-lead-carol", "SRE and incident lead", "carol-password-1", []string{"sre", "incident-lead"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: status %d", user, status)
		}
		return tok
	}
	oncall := login("sre-oncall", "oncall-password-1")
	second := login("sre-second", "second-password-1")
	bob := login("lead-bob", "bob-password-123")
	alice := login("dba-alice", "alice-password-1")
	carol := login("sre-lead-carol", "carol-password-1")
	oncallID, bobID := userIDOf(t, oncall), userIDOf(t, bob)

	stopService(t, recorder) // the emergency: nothing can be recorded

	request := func(t *testing.T, token string) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gateway.baseURL, token, accountID, true, reason, 10)
		if status != http.StatusCreated {
			t.Fatalf("request: %d %s", status, body)
		}
		if sess.Status != "pending_approval" {
			t.Fatalf("a break-glass request must wait for a second person, got status %q: %s", sess.Status, body)
		}
		return sess.ID
	}
	status := func(t *testing.T, token, id string) string {
		t.Helper()
		s, _ := gatewayGetSession(t, gateway.baseURL, token, id)["status"].(string)
		return s
	}
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen

	// The forged body a client would send to decide as somebody else, with a role it does not hold.
	forged := fmt.Sprintf(`{"decidedBy":%q,"actorRoles":["incident-lead","platform-admin"]}`, bobID)

	var s1 string
	linesBefore := len(targetSaw())

	t.Run("a break-glass request waits: it is not a session, and nothing was granted", func(t *testing.T) {
		s1 = request(t, oncall)
		spy.waitFor(t, "session.breakglass_requested", s1, true)
		settle()
		if spy.count("session.create", s1) != 0 {
			t.Fatal("a session.create was audited for a request nobody approved")
		}
		if st, body, ticket := gatewayConnectRaw(t, gateway.baseURL, oncall, s1); st != http.StatusConflict || ticket != "" {
			t.Fatalf("the requester connected to a request waiting for approval: %d %s", st, body)
		}
		if got := len(targetSaw()); got != linesBefore {
			t.Fatalf("the target received something: %q", targetSaw())
		}
	})

	t.Run("nobody approves their own request — whatever the body says, whatever roles they hold", func(t *testing.T) {
		st, body := gatewayDecide(t, gateway.baseURL, oncall, s1, "approve", forged)
		if st != http.StatusForbidden || !strings.Contains(body, "person who made it") {
			t.Fatalf("the requester approved their own request: %d %s", st, body)
		}
		// Carol is allowed to ask AND to approve: it is her identity, not her role, that is compared.
		s2 := request(t, carol)
		if st, body := gatewayDecide(t, gateway.baseURL, carol, s2, "approve", `{}`); st != http.StatusForbidden || !strings.Contains(body, "person who made it") {
			t.Fatalf("a requester who also holds the approval policy approved their own request: %d %s", st, body)
		}
		spy.waitFor(t, "session.breakglass_approved", s1, false)
		spy.waitFor(t, "session.breakglass_approved", s2, false)
		if spy.has("session.breakglass_approved", s1, true) || spy.has("session.breakglass_approved", s2, true) {
			t.Fatal("a refused self-approval was audited as a success")
		}
		if status(t, oncall, s1) != "pending_approval" || status(t, carol, s2) != "pending_approval" {
			t.Fatal("a refused approval changed a request")
		}
		// And the proof that the second person is the whole difference: Bob can approve Carol's.
		if st, body := gatewayDecide(t, gateway.baseURL, bob, s2, "approve", `{}`); st != http.StatusOK {
			t.Fatalf("the control failed: a second person could not approve: %d %s", st, body)
		}
	})

	t.Run("the right to ask is not the right to approve; a forged body decides nothing", func(t *testing.T) {
		for name, token := range map[string]string{"another SRE who may ask": second, "a DBA": alice} {
			st, body := gatewayDecide(t, gateway.baseURL, token, s1, "approve", forged)
			if st != http.StatusForbidden || !strings.Contains(body, "no approval policy") {
				t.Fatalf("%s approved: %d %s", name, st, body)
			}
		}
		spy.waitFor(t, "session.breakglass_approved", s1, false)
		if status(t, oncall, s1) != "pending_approval" {
			t.Fatal("an unauthorised approval changed the request")
		}
		if actor, _ := spy.actorOf("session.breakglass_approved", s1, false); actor == bobID {
			t.Fatal("the refusal was attributed to Bob, whose name the forged body carried")
		}
	})

	t.Run("a stranger cannot kill someone's request either", func(t *testing.T) {
		if st, body := gatewayDecide(t, gateway.baseURL, alice, s1, "reject", forged); st != http.StatusForbidden {
			t.Fatalf("a user with no approval authority rejected a request: %d %s", st, body)
		}
		if status(t, oncall, s1) != "pending_approval" {
			t.Fatal("the request did not survive a stranger")
		}
	})

	t.Run("the incident lead approves — as himself, with his own roles, whatever the body says", func(t *testing.T) {
		// The body names somebody else and no roles at all: a Gateway that believed it would
		// refuse (no roles) or attribute the decision to a stranger.
		st, body := gatewayDecide(t, gateway.baseURL, bob, s1, "approve", `{"decidedBy":"u-forged","actorRoles":[]}`)
		if st != http.StatusOK {
			t.Fatalf("approve: %d %s", st, body)
		}
		var out map[string]any
		_ = json.Unmarshal([]byte(body), &out)
		if out["status"] != "active" || out["decidedBy"] != bobID || out["requestedBy"] != oncallID {
			t.Fatalf("approved = %s (want decidedBy %s, requestedBy %s)", body, bobID, oncallID)
		}
		spy.waitFor(t, "session.breakglass_approved", s1, true)
		if actor, _ := spy.actorOf("session.breakglass_approved", s1, true); actor != bobID {
			t.Fatalf("the approval is attributed to %q, want Bob (%s)", actor, bobID)
		}
		if actor, _ := spy.actorOf("session.breakglass_requested", s1, true); actor != oncallID {
			t.Fatalf("the request is attributed to %q, want the on-call (%s)", actor, oncallID)
		}
	})

	t.Run("the approver cannot use what he approved, nor can anybody else", func(t *testing.T) {
		before := len(targetSaw())
		for name, token := range map[string]string{"the approver": bob, "a bystander": alice, "another SRE": second} {
			st, body, ticket := gatewayConnectRaw(t, gateway.baseURL, token, s1)
			if st != http.StatusForbidden || ticket != "" {
				t.Fatalf("%s got a connection: %d %s", name, st, body)
			}
		}
		settle()
		if len(targetSaw()) != before {
			t.Fatal("the target received something from a refused connect")
		}
	})

	t.Run("the requester runs the approved session while the recorder is down, and the trail says so", func(t *testing.T) {
		_, ticket, st := gatewayConnect(t, gateway.baseURL, oncall, s1)
		if st != http.StatusOK {
			t.Fatalf("the requester could not connect to an approved session: %d", st)
		}
		sh := openShell(t, "127.0.0.1:18716", ticket)
		fmt.Fprint(sh.stdin, "systemctl restart postgresql\r")
		sh.waitFor("out:systemctl restart postgresql")
		found := false
		for _, l := range targetSaw() {
			if l == "systemctl restart postgresql" {
				found = true
			}
		}
		if !found {
			t.Fatalf("the command did not reach the target: %q", targetSaw())
		}
		// Four facts in the chain: who asked, who approved, that the waiver was USED.
		spy.waitFor(t, "session.breakglass_requested", s1, true)
		spy.waitFor(t, "session.breakglass_approved", s1, true)
		spy.waitFor(t, "session.breakglass", s1, true)
	})

	t.Run("a decision is taken once", func(t *testing.T) {
		for _, action := range []string{"approve", "reject"} {
			if st, body := gatewayDecide(t, gateway.baseURL, bob, s1, action, `{}`); st != http.StatusConflict {
				t.Fatalf("%s on a decided request: %d %s, want 409", action, st, body)
			}
		}
		if status(t, oncall, s1) == "denied" {
			t.Fatal("a second decision overturned the first")
		}
	})

	t.Run("a rejected request never opens", func(t *testing.T) {
		s3 := request(t, oncall)
		before := len(targetSaw())
		st, body := gatewayDecide(t, gateway.baseURL, bob, s3, "reject", forged)
		if st != http.StatusOK || !strings.Contains(body, `"status":"denied"`) || !strings.Contains(body, bobID) {
			t.Fatalf("reject: %d %s", st, body)
		}
		spy.waitFor(t, "session.breakglass_rejected", s3, true)
		if st, body, ticket := gatewayConnectRaw(t, gateway.baseURL, oncall, s3); st == http.StatusOK || ticket != "" {
			t.Fatalf("a rejected request connected: %d %s", st, body)
		}
		if st, body := gatewayDecide(t, gateway.baseURL, bob, s3, "approve", `{}`); st != http.StatusConflict {
			t.Fatalf("a rejected request was approved: %d %s", st, body)
		}
		settle()
		if len(targetSaw()) != before {
			t.Fatal("the target received something from a rejected request")
		}
	})

	t.Run("the edges: unknown session, no token, routes the Gateway does not know", func(t *testing.T) {
		if st, _ := gatewayDecide(t, gateway.baseURL, bob, "session_nope", "approve", `{}`); st != http.StatusNotFound {
			t.Fatalf("unknown session: %d, want 404", st)
		}
		if st, _ := gatewayDecide(t, gateway.baseURL, "", s1, "approve", `{}`); st != http.StatusUnauthorized {
			t.Fatalf("no token: %d, want 401", st)
		}
		if st, _ := gatewayDecide(t, gateway.baseURL, bob, s1, "approve/extra", `{}`); st != http.StatusNotFound {
			t.Fatalf("a deeper path: %d, want 404", st)
		}
		if st, _ := gatewayDecide(t, gateway.baseURL, bob, s1, "promote", `{}`); st != http.StatusNotFound {
			t.Fatalf("an unknown action: %d, want 404", st)
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

// The two new switches are read strictly: a value that is neither of the two words, or not a
// number in range, is an error naming the variable — never a quiet "required", never a
// quiet "disabled".
func TestBreakGlassApprovalConfig_TheBrokerRefusesToStartOnAnUnreadableValue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-approval-check")
	for _, bad := range []string{"none", "Required", "off", "true", "yes", "required "} {
		out := runUntilExit(t, root, bin, "PORT=18798", "BREAKGLASS_APPROVAL="+bad)
		if !strings.Contains(out, "BREAKGLASS_APPROVAL") {
			t.Fatalf("BREAKGLASS_APPROVAL=%q: expected an error naming the variable, got:\n%s", bad, out)
		}
	}
	for _, bad := range []string{"0", "-5", "1441", "abc", "15m", "1.5"} {
		out := runUntilExit(t, root, bin, "PORT=18798", "BREAKGLASS_APPROVAL_WINDOW_MINUTES="+bad)
		if !strings.Contains(out, "BREAKGLASS_APPROVAL_WINDOW_MINUTES") {
			t.Fatalf("BREAKGLASS_APPROVAL_WINDOW_MINUTES=%q: expected an error naming the variable, got:\n%s", bad, out)
		}
	}
}

// The weak mode is a choice that is announced, not a quiet default; and the strict one says
// what it requires.
func TestBreakGlassApprovalConfig_TheBrokerAnnouncesWhichModeItRuns(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-approval-announce")

	for _, c := range []struct {
		name, port string
		env        []string
		want       string
		notWant    string
	}{
		{"strict by default", "18799", []string{"BREAKGLASS_MAX_MINUTES=30"}, "needs the approval of a second user", "WITHOUT APPROVAL"},
		{"weak mode, by name", "18795", []string{"BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_APPROVAL=disabled"}, "WITHOUT APPROVAL", "needs the approval"},
	} {
		t.Run(c.name, func(t *testing.T) {
			cmd := exec.Command(bin)
			cmd.Env = append(buildEnv(root), append([]string{"PORT=" + c.port}, c.env...)...)
			var out syncBuffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
			waitUntil(t, 5*time.Second, "the Broker to announce its break-glass mode", func() bool {
				return strings.Contains(out.String(), "BREAK-GLASS ENABLED")
			})
			if !strings.Contains(out.String(), c.want) || strings.Contains(out.String(), c.notWant) {
				t.Fatalf("the announcement is wrong (want %q, not %q):\n%s", c.want, c.notWant, out.String())
			}
		})
	}
}

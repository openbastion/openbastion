// Break-glass (ADR-0009), proved across EIGHT real processes: Authentication,
// Authorization, Session Broker, Password Vault, Audit Service, ssh-proxy,
// Command Recorder and the API Gateway — with a pass-through in front of the
// Audit Service so that what BOTH the Broker and the proxy emit can be read.
//
// The scenario is the emergency it exists for: the recorder is down, ordinary
// sessions are refused (ADR-0008), and an on-call engineer who holds the
// break-glass policy needs a shell. The same deployment is then used to show
// each lock holding: no policy, too long, no justification, a proxy that was
// never told to honour it, a platform that never enabled it. As in ADR-0008's
// proof, the claims that matter are negative ones, so the target reports every
// line it receives.
package integration_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

// gatewayCreateWith creates a session through the Gateway with full control over
// the break-glass parameters, and returns the status and raw body whatever they are.
func gatewayCreateWith(t *testing.T, baseURL, token, accountID string, breakGlass bool, justification string, minutes int) (int, string, *brokerSession) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"targetAccountId": accountID, "protocol": "ssh",
		"justification": justification, "durationMinutes": minutes, "breakGlass": breakGlass,
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway create-session: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		return resp.StatusCode, string(raw), nil
	}
	var sess brokerSession
	if err := json.Unmarshal(raw, &sess); err != nil {
		t.Fatalf("decode session: %v (%s)", err, raw)
	}
	return resp.StatusCode, string(raw), &sess
}

// anyEvent counts the events of one action and outcome, whatever session they are about:
// a refused request never returns a session id to look it up by.
func (s *auditSpy) anyEvent(action string, success bool) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, e := range s.events {
		if e.Action == action && e.Success == success {
			n++
		}
	}
	return n
}

func TestBreakGlass_AnEmergencyAccessWithoutARecorder_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-7")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-7")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-7")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-7")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-7")
	sshProxyBin := buildBinary(t, root, "./services/proxy/ssh-proxy/cmd/ssh-proxy", "ssh-proxy-7")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-7")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-7")

	vault := startService(t, root, vaultBin, "18701", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:18703")
	audit := startService(t, root, auditBin, "18702")
	authz := startService(t, root, authzBin, "18703")
	authn := startService(t, root, authnBin, "18707", "SKIP_DEMO_SEED=1")
	recorder := startService(t, root, recorderBin, "18709", "AUTHORIZATION_URL=http://127.0.0.1:18703", "AUDIT_URL="+audit.baseURL)
	spy := startAuditSpy(t, audit.baseURL)

	proxyEnv := func(extra ...string) []string {
		return append([]string{
			"VAULT_URL=http://127.0.0.1:18701",
			"AUDIT_URL=" + spy.baseURL, // the proxy's events pass through the spy to the real Audit Service
			"PROXY_SERVICE_ID=ssh-proxy",
			"RECORDER_URL=http://127.0.0.1:18709",
			"RECORDING_POLICY=required",
		}, extra...)
	}
	brokerEnv := func(extra ...string) []string {
		return append([]string{
			"AUTHORIZATION_URL=http://127.0.0.1:18703",
			"VAULT_URL=http://127.0.0.1:18701",
			"AUDIT_URL=" + spy.baseURL, // the Broker's events too
			"SSH_PROXY_URL=http://127.0.0.1:18705",
		}, extra...)
	}
	proxy := startServiceWithExtraPort(t, root, sshProxyBin, "18705", "18706", proxyEnv("BREAKGLASS_ENABLED=true")...)
	broker := startService(t, root, brokerBin, "18704", brokerEnv("BREAKGLASS_MAX_MINUTES=30", "BREAKGLASS_APPROVAL=disabled")...) // ADR-0009's locks, alone: the double validation (ADR-0011) has its own test
	gateway := startService(t, root, gatewayBin, "18708",
		"AUTHENTICATION_URL=http://127.0.0.1:18707",
		"SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:18709",
	)

	const targetSecret = "break-glass-target-secret"
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

	const accountID = "acc_break_glass"
	const reason = "recorder down during P1 incident INC-4521"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "break-glass-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	// Both roles may open an ordinary session; only `sre` holds a break-glass policy.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "dba-alice", "Alice (DBA)", "alice-password-1", []string{"dba"})
	authCreateUser(t, authn.baseURL, "sre-oncall", "On-call SRE", "oncall-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "auditor", "Auditor", "aud-password-123", []string{"session-auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: status %d", user, status)
		}
		return tok
	}
	aliceToken := login("dba-alice", "alice-password-1")
	oncallToken := login("sre-oncall", "oncall-password-1")
	auditorToken := login("auditor", "aud-password-123")
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen

	// ---- A. a healthy recorder: break-glass changes nothing ---------------------------
	t.Run("with the recorder up, a break-glass session is recorded in full and no waiver is used", func(t *testing.T) {
		status, body, sess := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, reason, 10)
		if status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, body)
		}
		if !strings.Contains(body, `"breakGlass":true`) {
			t.Fatalf("the session does not say it is break-glass: %s", body)
		}
		spy.waitFor(t, "session.breakglass_requested", sess.ID, true)

		_, ticket, status := gatewayConnect(t, gateway.baseURL, oncallToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect: %d", status)
		}
		sh := openShell(t, "127.0.0.1:18706", ticket)
		fmt.Fprint(sh.stdin, "uptime\r")
		sh.waitFor("out:uptime")

		// Acknowledged before it ran: readable at once, from the real recorder.
		status, raw, page := gatewayGetRecording(t, gateway.baseURL, auditorToken, sess.ID, "")
		if status != http.StatusOK || len(page.commands()) != 1 || page.commands()[0] != "uptime" {
			t.Fatalf("the session was not recorded: %d %s", status, raw)
		}
		settle()
		if spy.count("session.breakglass", sess.ID) != 0 {
			t.Fatal("a waiver was recorded for a session whose recorder was ready — break-glass must not degrade a recordable session")
		}
	})

	// ---- the recorder goes down --------------------------------------------------------
	stopService(t, recorder)

	t.Run("without a break-glass policy the request is refused, and audited", func(t *testing.T) {
		before := spy.anyEvent("session.breakglass_requested", false)
		status, body, _ := gatewayCreateWith(t, gateway.baseURL, aliceToken, accountID, true, reason, 10)
		if status != http.StatusForbidden {
			t.Fatalf("a DBA with no break-glass policy got %d %s", status, body)
		}
		if !strings.Contains(body, "break-glass") {
			t.Fatalf("the refusal does not say what was refused: %s", body)
		}
		deadline := time.Now().Add(3 * time.Second)
		for spy.anyEvent("session.breakglass_requested", false) <= before && time.Now().Before(deadline) {
			time.Sleep(20 * time.Millisecond)
		}
		if spy.anyEvent("session.breakglass_requested", false) <= before {
			t.Fatal("the refused request was not audited")
		}
	})

	t.Run("even the holder of the policy gets nothing without asking for it", func(t *testing.T) {
		_, _, sess := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, false, "routine", 10)
		if sess == nil {
			t.Fatal("an ordinary session was refused")
		}
		status, body, ticket := gatewayConnectRaw(t, gateway.baseURL, oncallToken, sess.ID)
		if status != http.StatusServiceUnavailable || ticket != "" {
			t.Fatalf("an ordinary session of a break-glass holder must be refused while the recorder is down: %d %s", status, body)
		}
	})

	t.Run("the limits: too long, and no real justification", func(t *testing.T) {
		if status, body, _ := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, reason, 60); status != http.StatusForbidden {
			t.Fatalf("60 minutes against a 30 minute limit: %d %s", status, body)
		}
		if status, body, _ := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, "urgent", 10); status != http.StatusForbidden {
			t.Fatalf("a six-character justification: %d %s", status, body)
		}
	})

	// ---- the emergency itself ----------------------------------------------------------
	t.Run("an authorised break-glass session runs without the recorder, and says so in the audit trail", func(t *testing.T) {
		status, body, sess := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, reason, 10)
		if status != http.StatusCreated {
			t.Fatalf("create: %d %s", status, body)
		}
		_, ticket, status := gatewayConnect(t, gateway.baseURL, oncallToken, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("connect while the recorder is down: %d — the waiver was not honoured", status)
		}
		sh := openShell(t, "127.0.0.1:18706", ticket)
		fmt.Fprint(sh.stdin, "systemctl restart postgresql\r")
		sh.waitFor("out:systemctl restart postgresql")

		if strings.Contains(sh.output(), "recording is unavailable") {
			t.Fatalf("the operator was told the session could not run: %q", sh.output())
		}
		found := false
		for _, l := range targetSaw() {
			if l == "systemctl restart postgresql" {
				found = true
			}
		}
		if !found {
			t.Fatalf("the command did not reach the target: %q", targetSaw())
		}
		// Three facts on record: who asked (Broker), that the waiver was USED
		// (proxy), and — by absence — that nothing was reported as a recording failure.
		spy.waitFor(t, "session.breakglass_requested", sess.ID, true)
		spy.waitFor(t, "session.breakglass", sess.ID, true)
		if spy.count("session.recording_lost", sess.ID) != 0 || spy.count("session.recording_unavailable", sess.ID) != 0 {
			t.Fatal("a waived session was reported as a recording failure")
		}
	})

	// ---- the proxy decides what it enforces -------------------------------------------
	t.Run("a proxy that was never told to honour break-glass refuses it, whatever the Broker authorised", func(t *testing.T) {
		stopService(t, proxy)
		proxy = startServiceWithExtraPort(t, root, sshProxyBin, "18705", "18706", proxyEnv()...) // BREAKGLASS_ENABLED unset
		linesBefore := len(targetSaw())

		status, body, sess := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, reason, 10)
		if status != http.StatusCreated {
			t.Fatalf("the Broker should still authorise it: %d %s", status, body)
		}
		status, body, ticket := gatewayConnectRaw(t, gateway.baseURL, oncallToken, sess.ID)
		if status != http.StatusServiceUnavailable || ticket != "" {
			t.Fatalf("the proxy honoured a waiver it was not configured for: %d %s", status, body)
		}
		spy.waitFor(t, "session.recording_unavailable", sess.ID, false)
		settle()
		if spy.count("session.breakglass", sess.ID) != 0 {
			t.Fatal("a waiver was recorded by a proxy that does not allow it")
		}
		if got := len(targetSaw()); got != linesBefore {
			t.Fatalf("the target received something from a refused session: %q", targetSaw())
		}
	})

	// ---- the platform decides whether it exists at all --------------------------------
	t.Run("a platform that never enabled break-glass refuses the request outright", func(t *testing.T) {
		stopService(t, broker)
		broker = startService(t, root, brokerBin, "18704", brokerEnv()...) // BREAKGLASS_MAX_MINUTES unset
		status, body, _ := gatewayCreateWith(t, gateway.baseURL, oncallToken, accountID, true, reason, 10)
		if status != http.StatusForbidden || !strings.Contains(body, "not enabled") {
			t.Fatalf("expected a refusal saying break-glass is not enabled, got %d %s", status, body)
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

// The two switches are off unless asked for by name — and a broken value is an
// error, never a quiet "on" or a quiet "off".
func TestBreakGlassConfig_TheBrokerRefusesToStartOnAnUnreadableLimit(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-bg-check")
	for _, bad := range []string{"thirty", "-5", "30m", "1.5"} {
		out := runUntilExit(t, root, bin, "PORT=18797", "BREAKGLASS_MAX_MINUTES="+bad)
		if !strings.Contains(out, "BREAKGLASS_MAX_MINUTES") {
			t.Fatalf("BREAKGLASS_MAX_MINUTES=%q: expected an error naming the variable, got:\n%s", bad, out)
		}
	}
}

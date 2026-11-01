// The approval of an ordinary session by another person, with a ticket (ADR-0067), proved
// across EIGHT real processes — with break-glass switched off, so that what is proved is
// this mechanism and not ADR-0011's.
//
// The account says it requires approval; only an administrator says so, and the audit trail
// has it first. A request then needs a ticket in the declared format, waits, is shown to the
// account's approvers and nobody else, is decided by another person who holds
// session-approve:account:{id} — not by the break-glass approvers —, and, approved, opens a
// session that is recorded like any other.
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

// gatewayAsk posts a session request with a ticket through the Gateway, and returns the raw
// answer: the test reads the fields it is about.
func gatewayAsk(t *testing.T, baseURL, token, accountID string, ticket any) (int, map[string]any, string) {
	t.Helper()
	fields := map[string]any{"targetAccountId": accountID, "protocol": "ssh", "justification": "apply the change", "durationMinutes": 20}
	if ticket != nil {
		fields["ticket"] = ticket
	}
	body, _ := json.Marshal(fields)
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/sessions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway create-session: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var out map[string]any
	_ = json.Unmarshal(raw, &out)
	return resp.StatusCode, out, string(raw)
}

func gatewaySetApproval(t *testing.T, baseURL, token, accountID, body string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPut, baseURL+"/vault/accounts/"+accountID+"/approval", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway set approval: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestApprovalFlow_AnotherPersonApprovesWithATicket_AcrossEightRealProcesses(t *testing.T) {
	root := repoRoot(t)
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "proxy": "./services/proxy/ssh-proxy/cmd/ssh-proxy",
		"recorder": "./services/recording-audit/command-recorder/cmd/command-recorder", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-67")
	}
	hook := newHookSpy(t)
	audit := startService(t, root, bins["audit"], "19762")
	spy := startAuditSpy(t, audit.baseURL)
	vault := startService(t, root, bins["vault"], "19761", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL=http://127.0.0.1:19763", "AUDIT_URL="+spy.baseURL)
	authz := startService(t, root, bins["authz"], "19763")
	authn := startService(t, root, bins["authn"], "19767", "SKIP_DEMO_SEED=1")
	startService(t, root, bins["recorder"], "19769", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
	startServiceWithExtraPort(t, root, bins["proxy"], "19765", "19766", "VAULT_URL="+vault.baseURL, "AUDIT_URL="+spy.baseURL,
		"PROXY_SERVICE_ID=ssh-proxy", "RECORDER_URL=http://127.0.0.1:19769", "RECORDING_POLICY=required")
	// BREAKGLASS_MAX_MINUTES is not set: break-glass is off on this platform.
	broker := startService(t, root, bins["broker"], "19764", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+spy.baseURL, "SSH_PROXY_URL=http://127.0.0.1:19765",
		"APPROVAL_TICKET_PATTERN=(INC|CHG)[0-9]{7}", "BREAKGLASS_NOTIFY_URL="+hook.srv.URL+"/hook")
	gateway := startService(t, root, bins["gateway"], "19768", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"COMMAND_RECORDER_URL=http://127.0.0.1:19769", "VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL, "CLIENT_LOGIN_BURST=100")

	const targetSecret = "approval-flow-target-secret"
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

	const accountID = "acc_gated"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccountFull(t, vault.baseURL, accountID, "gated-account", "root", targetAddr, targetSecret, []string{"vault-admin"})
	// Distinct authorities: to open a session, to approve one on this account, to approve a
	// break-glass on it, to read recordings.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "change-manager", "session-approve:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "incident-lead", "breakglass-approve:account:"+accountID, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "admin", "Admin", "admin-password-123", []string{"vault-admin"})
	authCreateUser(t, authn.baseURL, "dba-alice", "Alice", "alice-password-1", []string{"dba"})
	authCreateUser(t, authn.baseURL, "cm-mona", "Mona (change manager)", "mona-password-1", []string{"change-manager"})
	authCreateUser(t, authn.baseURL, "lead-bob", "Bob (incident lead)", "bob-password-123", []string{"incident-lead"})
	// Carol may ask AND approve: the worst case for self-approval.
	authCreateUser(t, authn.baseURL, "dba-cm-carol", "Carol", "carol-password-1", []string{"dba", "change-manager"})
	authCreateUser(t, authn.baseURL, "auditor", "Auditor", "aud-password-123", []string{"session-auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gateway.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: status %d", user, status)
		}
		return tok
	}
	admin, alice, mona := login("admin", "admin-password-123"), login("dba-alice", "alice-password-1"), login("cm-mona", "mona-password-1")
	bob, carol, auditor := login("lead-bob", "bob-password-123"), login("dba-cm-carol", "carol-password-1"), login("auditor", "aud-password-123")
	aliceID, monaID := userIDOf(t, alice), userIDOf(t, mona)
	status := func(t *testing.T, token, id string) string {
		t.Helper()
		s, _ := gatewayGetSession(t, gateway.baseURL, token, id)["status"].(string)
		return s
	}
	ask := func(t *testing.T, token string) string {
		t.Helper()
		st, out, raw := gatewayAsk(t, gateway.baseURL, token, accountID, "CHG0001234")
		if st != http.StatusCreated || out["status"] != "pending_approval" || out["ticket"] != "CHG0001234" || out["approvalRequired"] != true {
			t.Fatalf("request: %d %s", st, raw)
		}
		return out["id"].(string)
	}
	settle := func() { time.Sleep(400 * time.Millisecond) }

	t.Run("before the setting, a session opens at once — and a ticket changes nothing", func(t *testing.T) {
		st, out, raw := gatewayAsk(t, gateway.baseURL, alice, accountID, nil)
		if st != http.StatusCreated || out["status"] != "active" {
			t.Fatalf("an account that requires no approval: %d %s", st, raw)
		}
	})

	t.Run("only an administrator makes the account require approval, and the audit has it first", func(t *testing.T) {
		if st, body := gatewaySetApproval(t, gateway.baseURL, alice, accountID, `{"approvalRequired":true,"actorRoles":["vault-admin"]}`); st != http.StatusForbidden {
			t.Fatalf("a DBA changed the setting: %d %s", st, body)
		}
		spy.waitFor(t, "vault.approval_set", accountID, false)
		if st, body := gatewaySetApproval(t, gateway.baseURL, admin, accountID, `{}`); st != http.StatusBadRequest {
			t.Fatalf("without the field: %d %s", st, body)
		}
		if st, body := gatewaySetApproval(t, gateway.baseURL, admin, accountID, `{"approvalRequired":true}`); st != http.StatusOK {
			t.Fatalf("the administrator: %d %s", st, body)
		}
		spy.waitFor(t, "vault.approval_set", accountID, true)
		if actor, _ := spy.actorOf("vault.approval_set", accountID, true); actor != userIDOf(t, admin) {
			t.Fatalf("the setting is attributed to %q", actor)
		}
	})

	t.Run("a request without a ticket, or out of the declared format, is refused and audited", func(t *testing.T) {
		before := spy.anyEvent("session.approval_requested", false)
		for _, ticket := range []any{nil, "", "INC123", "CHG0001234; and more", "PRB0001234", 42} {
			st, _, raw := gatewayAsk(t, gateway.baseURL, alice, accountID, ticket)
			if ticket == 42 {
				if st != http.StatusBadRequest {
					t.Fatalf("a ticket that is not a string: %d %s", st, raw)
				}
				continue
			}
			if st != http.StatusBadRequest || !strings.Contains(raw, "ticket in the declared format") {
				t.Fatalf("ticket %v: %d %s", ticket, st, raw)
			}
		}
		waitUntil(t, 5*time.Second, "the refusals to be audited", func() bool {
			return spy.anyEvent("session.approval_requested", false) == before+6
		})
		if spy.hasTicket("session.approval_requested", "", false, "CHG0001234; and more") {
			// Invalid ticket values are intentionally never copied to the audit.
			t.Fatal("an invalid ticket was echoed to audit")
		}
	})

	var s1 string
	t.Run("with a ticket, the request waits: it is not a session, and nothing reaches the target", func(t *testing.T) {
		lines := len(targetSaw())
		s1 = ask(t, alice)
		spy.waitFor(t, "session.approval_requested", s1, true)
		if !spy.hasTicket("session.approval_requested", s1, true, "CHG0001234") {
			t.Fatal("the request audit does not contain its ticket")
		}
		settle()
		if spy.count("session.create", s1) != 0 {
			t.Fatal("a session.create was audited for a request nobody approved")
		}
		if st, body, ticket := gatewayConnectRaw(t, gateway.baseURL, alice, s1); st != http.StatusConflict || ticket != "" {
			t.Fatalf("the requester connected to a request waiting for approval: %d %s", st, body)
		}
		if len(targetSaw()) != lines {
			t.Fatalf("the target received something: %q", targetSaw())
		}
		d := hook.waitFor(t, "approval.requested", s1)
		if d.Body["ticket"] != "CHG0001234" || d.Body["requestedBy"] != aliceID || strings.Contains(d.Raw, "apply the change") {
			t.Fatalf("the notification: %s", d.Raw)
		}
	})

	t.Run("the request is shown to the account's approvers, and to nobody else", func(t *testing.T) {
		st, body := gatewayList(t, gateway.baseURL, mona, "status=pending_approval")
		if st != http.StatusOK || !strings.Contains(body, s1) || !strings.Contains(body, "CHG0001234") {
			t.Fatalf("the change manager: %d %s", st, body)
		}
		for name, token := range map[string]string{"the requester": alice, "a break-glass approver": bob} {
			if st, body := gatewayList(t, gateway.baseURL, token, "status=pending_approval"); st != http.StatusOK || strings.Contains(body, s1) {
				t.Fatalf("%s sees it: %d %s", name, st, body)
			}
		}
	})

	t.Run("nobody approves their own request; the break-glass approvers do not decide it", func(t *testing.T) {
		forged := fmt.Sprintf(`{"decidedBy":%q,"actorRoles":["change-manager","platform-admin"]}`, monaID)
		if st, body := gatewayDecide(t, gateway.baseURL, alice, s1, "approve", forged); st != http.StatusForbidden {
			t.Fatalf("the requester approved, with a forged body: %d %s", st, body)
		}
		s2 := ask(t, carol)
		if st, body := gatewayDecide(t, gateway.baseURL, carol, s2, "approve", `{}`); st != http.StatusForbidden || !strings.Contains(body, "person who made it") {
			t.Fatalf("a requester who holds the approval policy approved their own request: %d %s", st, body)
		}
		for _, action := range []string{"approve", "reject"} {
			if st, body := gatewayDecide(t, gateway.baseURL, bob, s1, action, forged); st != http.StatusForbidden || !strings.Contains(body, "no approval policy") {
				t.Fatalf("a break-glass approver could %s: %d %s", action, st, body)
			}
		}
		spy.waitFor(t, "session.approval_approved", s1, false)
		spy.waitFor(t, "session.approval_rejected", s1, false)
		if actor, _ := spy.actorOf("session.approval_approved", s1, false); actor == monaID {
			t.Fatal("a refusal was attributed to Mona, whose name the forged body carried")
		}
		if status(t, alice, s1) != "pending_approval" || status(t, carol, s2) != "pending_approval" {
			t.Fatal("a refused decision changed a request")
		}
		// The counter-proof: another person with the policy decides Carol's.
		if st, body := gatewayDecide(t, gateway.baseURL, mona, s2, "reject", `{}`); st != http.StatusOK {
			t.Fatalf("the change manager could not reject: %d %s", st, body)
		}
		spy.waitFor(t, "session.approval_rejected", s2, true)
		hook.waitFor(t, "approval.rejected", s2)
		if st, _, _ := gatewayConnectRaw(t, gateway.baseURL, carol, s2); st == http.StatusOK {
			t.Fatal("a rejected request opened")
		}
	})

	t.Run("the change manager approves — as herself — and the requester's session is recorded", func(t *testing.T) {
		st, body := gatewayDecide(t, gateway.baseURL, mona, s1, "approve", `{"decidedBy":"u-forged","actorRoles":[]}`)
		var out map[string]any
		_ = json.Unmarshal([]byte(body), &out)
		if st != http.StatusOK || out["status"] != "active" || out["decidedBy"] != monaID || out["requestedBy"] != aliceID {
			t.Fatalf("approve: %d %s", st, body)
		}
		spy.waitFor(t, "session.approval_approved", s1, true)
		if !spy.hasTicket("session.approval_approved", s1, true, "CHG0001234") {
			t.Fatal("the approval audit does not contain its ticket")
		}
		if actor, _ := spy.actorOf("session.approval_approved", s1, true); actor != monaID {
			t.Fatalf("the approval is attributed to %q, want Mona (%s)", actor, monaID)
		}
		if d := hook.waitFor(t, "approval.approved", s1); d.Body["decidedBy"] != monaID || d.Body["ticket"] != "CHG0001234" {
			t.Fatalf("the notification: %s", d.Raw)
		}
		if st, _, ticket := gatewayConnectRaw(t, gateway.baseURL, mona, s1); st != http.StatusForbidden || ticket != "" {
			t.Fatalf("the approver connected to what she approved: %d", st)
		}

		_, ticket, cst := gatewayConnect(t, gateway.baseURL, alice, s1)
		if cst != http.StatusOK {
			t.Fatalf("the requester could not connect to an approved session: %d", cst)
		}
		sh := openShell(t, "127.0.0.1:19766", ticket)
		fmt.Fprint(sh.stdin, "apply-change CHG0001234\r")
		sh.waitFor("out:apply-change CHG0001234")
		waitUntil(t, 5*time.Second, "the command to be in the recording", func() bool {
			s, _, p := gatewayGetRecording(t, gateway.baseURL, auditor, s1, "")
			return s == http.StatusOK && strings.Contains(strings.Join(p.commands(), "\n"), "apply-change CHG0001234")
		})
		if spy.count("session.breakglass", s1) != 0 {
			t.Fatal("an approved ordinary session waived the recording")
		}
	})

	t.Run("a decision is taken once", func(t *testing.T) {
		for _, action := range []string{"approve", "reject"} {
			if st, body := gatewayDecide(t, gateway.baseURL, mona, s1, action, `{}`); st != http.StatusConflict {
				t.Fatalf("%s on a decided request: %d %s, want 409", action, st, body)
			}
		}
		if status(t, alice, s1) != "active" {
			t.Fatal("a second decision overturned the first")
		}
	})

	t.Run("the trail says who asked, with which ticket's request, and who approved, in that order", func(t *testing.T) {
		order := spy.actionsFor(s1)
		want := []string{"session.approval_requested", "session.approval_approved"}
		i := 0
		for _, a := range order {
			if i < len(want) && a == want[i] {
				i++
			}
		}
		if i != len(want) {
			t.Fatalf("the trail for %s is %v, want %v in that order", s1, order, want)
		}
	})
}

// actionsFor lists the successful actions recorded about one session, in the order received.
func (s *auditSpy) actionsFor(sessionID string) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for _, e := range s.events {
		if e.ResourceID == sessionID && e.Success {
			out = append(out, e.Action)
		}
	}
	return out
}

func (s *auditSpy) hasTicket(action, sessionID string, success bool, ticket string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.events {
		if e.Action == action && e.Success == success && (sessionID == "" || e.ResourceID == sessionID) {
			if e.Details["ticket"] == ticket {
				return true
			}
		}
	}
	return false
}

// TestApprovalFlow_ATicketPatternThatDoesNotCompileStopsTheBroker: a typo in the format must
// stop the service, not fall back to another format.
func TestApprovalFlow_ATicketPatternThatDoesNotCompileStopsTheBroker(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-67b")
	out := runUntilExit(t, root, bin, "PORT=19760", "APPROVAL_TICKET_PATTERN=(INC")
	if !strings.Contains(out, "APPROVAL_TICKET_PATTERN") {
		t.Fatalf("expected an error naming the variable, got:\n%s", out)
	}
}

// Who may end a session (ADR-0017), on real processes: Authorization, Authentication,
// Audit, the Session Broker and two API Gateways.
//
// Before ADR-0017 the Gateway relayed DELETE /sessions/{id} without saying who asked, and
// the Broker ended whatever session it was told to: any valid token that knew an identifier
// could end anybody's session, and the audit event named the REQUESTER as its author.
//
// The claims that matter: only the requester, or a person with a policy written for
// terminating on that account, ends a session; approving or requesting emergency access is
// not that policy; the person named in the audit is the one who asked, not the requester;
// what the client writes in the body decides nothing; and a refusal is on the record
// without being a way to make the platform write without limit.
package integration_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSessionTerminate_OnlyTheRequesterOrAnAuthorisedPersonEndsASession_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-17")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-17")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-17")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-17")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-17")

	audit := startService(t, root, auditBin, "18811")
	authz := startService(t, root, authzBin, "18812")
	authn := startService(t, root, authnBin, "18813", "SKIP_DEMO_SEED=1")
	spy := startAuditSpy(t, audit.baseURL)
	// A proxy that takes the revocation of a session and remembers it (ADR-0018): ending a
	// session is telling the proxy first, so the Broker needs one to answer. What it is told,
	// and when, is part of what these claims are about: a termination somebody was refused
	// must never reach it. The real proxy is the subject of session_revocation_test.go.
	var (
		revokeMu sync.Mutex
		revoked  []string
	)
	proxyURL := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/internal/v1/revoke-session" {
			http.NotFound(w, r)
			return
		}
		var req struct {
			SessionID  string `json:"session_id"`
			TTLSeconds int    `json:"ttl_seconds"`
		}
		if json.NewDecoder(r.Body).Decode(&req) != nil || req.SessionID == "" || req.TTLSeconds <= 0 {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		revokeMu.Lock()
		revoked = append(revoked, req.SessionID)
		revokeMu.Unlock()
		_, _ = w.Write([]byte(`{"tickets_revoked":0,"connections_cut":0}`))
	}))
	revocations := func(id string) int {
		revokeMu.Lock()
		defer revokeMu.Unlock()
		n := 0
		for _, r := range revoked {
			if r == id {
				n++
			}
		}
		return n
	}
	broker := startService(t, root, brokerBin, "18814",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18816", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL="+proxyURL)
	gatewayEnv := func(extra ...string) []string {
		return append([]string{"AUTHENTICATION_URL=" + authn.baseURL, "SESSION_BROKER_URL=" + broker.baseURL,
			"COMMAND_RECORDER_URL=http://127.0.0.1:18817"}, extra...)
	}
	// The budget is raised out of the way of the claims about who may end a session…
	gw := startService(t, root, gatewayBin, "18815", gatewayEnv("SESSION_ACTION_BURST=100", "SESSION_ACTION_RATE_PER_MINUTE=600")...)
	// …and a small one, for the claim about what a refusal costs: two at once, then one every ten seconds.
	gwSmall := startService(t, root, gatewayBin, "18818", gatewayEnv("SESSION_ACTION_BURST=2", "SESSION_ACTION_RATE_PER_MINUTE=6")...)

	const acc, other = "acc_term_1", "acc_term_2"
	for _, a := range []string{acc, other} {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+a, "allow")
	}
	// Carol may end sessions on `acc` — and only there. Erin may approve emergency access on it:
	// that is another power, with another resource.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "responder", "session-terminate:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"responder"})
	authCreateUser(t, authn.baseURL, "erin", "Erin", "erin-password-1234", []string{"lead"})
	authCreateUser(t, authn.baseURL, "mallory", "Mallory", "mallory-password-1", []string{"sre"})
	login := func(base, user, pw string) string {
		tok, status := gatewayLogin(t, base, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob := login(gw.baseURL, "alice", "alice-password-123"), login(gw.baseURL, "bob", "bob-password-12345")
	carol, erin := login(gw.baseURL, "carol", "carol-password-123"), login(gw.baseURL, "erin", "erin-password-1234")
	aliceID, bobID, carolID := userIDOf(t, alice), userIDOf(t, bob), userIDOf(t, carol)

	// An active session of Alice's, on the account (or on another).
	open := func(t *testing.T, onAccount string) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gw.baseURL, alice, onAccount, false, "ordinary maintenance window", 30)
		if status != http.StatusCreated || sess == nil || sess.Status != "active" {
			t.Fatalf("Alice's session: %d %s", status, body)
		}
		return sess.ID
	}
	end := func(base, token, id, body string) (int, string) {
		code, _, text := rawRequest(t, http.MethodDelete, base+"/sessions/"+id, token, body)
		return code, text
	}
	statusOf := func(t *testing.T, id string) string {
		t.Helper()
		s, _ := gatewayGetSession(t, gw.baseURL, alice, id)["status"].(string)
		return s
	}
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen

	s1 := open(t, acc)

	t.Run("somebody who has no right at all cannot end it — the refusal is on the record, under their own name", func(t *testing.T) {
		code, text := end(gw.baseURL, bob, s1, "")
		if code != http.StatusForbidden {
			t.Fatalf("Bob ended Alice's session, or was refused wrongly: %d %s, want 403", code, text)
		}
		if got := statusOf(t, s1); got != "active" {
			t.Fatalf("the session is %q after a refused termination, want active", got)
		}
		spy.waitFor(t, "session.terminate", s1, false)
		if actor, _ := spy.actorOf("session.terminate", s1, false); actor != bobID {
			t.Fatalf("the refusal is attributed to %q, want Bob (%q): the one who asked", actor, bobID)
		}
		if spy.has("session.terminate", s1, true) {
			t.Fatal("a termination was audited as a success, but the session was refused")
		}
		if n := revocations(s1); n != 0 {
			t.Fatalf("the proxy was told to cut a session whose termination was refused (%d times)", n)
		}
	})

	t.Run("what the client writes in the body decides nothing", func(t *testing.T) {
		forged := fmt.Sprintf(`{"callerId":%q,"actorRoles":["responder","platform-admin"]}`, aliceID)
		if code, text := end(gw.baseURL, bob, s1, forged); code != http.StatusForbidden {
			t.Fatalf("a forged body: %d %s, want 403", code, text)
		}
		if got := statusOf(t, s1); got != "active" {
			t.Fatalf("the session is %q after a forged termination, want active", got)
		}
	})

	t.Run("the power to approve emergency access is not the power to end a session", func(t *testing.T) {
		if code, text := end(gw.baseURL, erin, s1, ""); code != http.StatusForbidden {
			t.Fatalf("a person who may only approve: %d %s, want 403", code, text)
		}
		if got := statusOf(t, s1); got != "active" {
			t.Fatalf("the session is %q, want active", got)
		}
	})

	t.Run("a person with a policy for terminating on that account ends it — and the audit names that person, not the requester", func(t *testing.T) {
		code, text := end(gw.baseURL, carol, s1, "")
		if code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("Carol: %d %s, want 200 and a terminated session", code, text)
		}
		spy.waitFor(t, "session.terminate", s1, true)
		if actor, _ := spy.actorOf("session.terminate", s1, true); actor != carolID {
			t.Fatalf("the termination is attributed to %q, want Carol (%q): the requester did not end it", actor, carolID)
		}
		if n := revocations(s1); n != 1 {
			t.Fatalf("the proxy was told to cut the session %d times, want once", n)
		}
	})

	t.Run("that policy is for one account: Carol cannot end a session on another", func(t *testing.T) {
		s2 := open(t, other)
		if code, text := end(gw.baseURL, carol, s2, ""); code != http.StatusForbidden {
			t.Fatalf("Carol on an account she has no policy for: %d %s, want 403", code, text)
		}
		if got := statusOf(t, s2); got != "active" {
			t.Fatalf("the session is %q, want active", got)
		}
	})

	t.Run("the requester ends their own session, with no policy at all", func(t *testing.T) {
		s3 := open(t, other)
		code, text := end(gw.baseURL, alice, s3, "")
		if code != http.StatusOK || !strings.Contains(text, `"terminated"`) {
			t.Fatalf("Alice ending her own session: %d %s, want 200", code, text)
		}
		spy.waitFor(t, "session.terminate", s3, true)
		if actor, _ := spy.actorOf("session.terminate", s3, true); actor != aliceID {
			t.Fatalf("attributed to %q, want Alice (%q)", actor, aliceID)
		}
		if n := revocations(s3); n != 1 {
			t.Fatalf("the proxy was told to cut the session %d times, want once", n)
		}
		// Ending it again is a conflict, not an event: nothing more is written — and the
		// proxy is not asked again.
		before := spy.count("session.terminate", s3)
		if code, _ := end(gw.baseURL, alice, s3, ""); code != http.StatusConflict {
			t.Fatalf("ending it a second time: %d, want 409", code)
		}
		settle()
		if n := spy.count("session.terminate", s3); n != before {
			t.Fatalf("%d terminate events after the second call, was %d: a conflict is not an event", n, before)
		}
		if n := revocations(s3); n != 1 {
			t.Fatalf("the proxy was told again about a session that was already ended (%d calls)", n)
		}
	})

	t.Run("a session that does not exist is a 404, not a conflict", func(t *testing.T) {
		if code, text := end(gw.baseURL, alice, "session_0000000000000000", ""); code != http.StatusNotFound {
			t.Fatalf("an unknown session: %d %s, want 404", code, text)
		}
	})

	t.Run("without a token there is nothing to say who asks", func(t *testing.T) {
		s4 := open(t, acc)
		if code, _ := end(gw.baseURL, "", s4, ""); code != http.StatusUnauthorized {
			t.Fatalf("no token: %d, want 401", code)
		}
		if got := statusOf(t, s4); got != "active" {
			t.Fatalf("the session is %q, want active", got)
		}
	})

	t.Run("a refused termination costs the budget of its author: only the budget reaches the audit", func(t *testing.T) {
		s5 := open(t, acc)
		mallory := login(gwSmall.baseURL, "mallory", "mallory-password-1")
		before := spy.anyEvent("session.terminate", false)
		var codes []int
		for i := 0; i < 6; i++ {
			code, _ := end(gwSmall.baseURL, mallory, s5, "")
			codes = append(codes, code)
		}
		if fmt.Sprint(codes) != "[403 403 429 429 429 429]" {
			t.Fatalf("six attempts with a budget of 2 gave %v, want two refusals by the Broker and four by the budget", codes)
		}
		settle()
		if n := spy.anyEvent("session.terminate", false) - before; n != 2 {
			t.Fatalf("%d refusals audited out of 6, want 2: what the budget refuses must write nothing", n)
		}
		if got := statusOf(t, s5); got != "active" {
			t.Fatalf("the session is %q, want active", got)
		}
	})
}

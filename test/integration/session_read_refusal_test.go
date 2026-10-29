package integration_test

// A refused read of a session is on the record (ADR-0020), across real processes —
// Authentication, Authorization, Audit (behind a spy), the Session Broker and the Gateway.
//
// Before ADR-0020 a refusal of GET /sessions/{id} left no trace anywhere: somebody who held
// the identifier of a session and tried to read it, again and again, was visible nowhere.
// This is that, written first and seen to fail.
//
// The claims: a refused read is an audit event under the name of the one who asked — the
// verified token's, whatever the client writes in the query; it is bounded by a budget per
// identity, so that a refusal is not a way to write without limit into the trail, while the
// refusals themselves are never softened; the budget is each identity's own; and what is
// not a refusal — a read that is served, a session that does not exist — writes nothing.

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestSessionReadRefusal_IsOnTheRecordUnderTheNameOfWhoAsked_WithinABudget_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-20")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-20")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-20")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-20")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-20")

	audit := startService(t, root, auditBin, "18961")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "18962")
	authn := startService(t, root, authnBin, "18963", "SKIP_DEMO_SEED=1")
	// A budget of 3 refusals at once, then one a minute: small enough to spend in a test.
	broker := startService(t, root, brokerBin, "18964",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18966", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18967",
		"SESSION_READ_AUDIT_BURST=3", "SESSION_READ_AUDIT_RATE_PER_MINUTE=1")
	gw := startService(t, root, gatewayBin, "18965",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:18967")

	const acc = "acc_refusal_1"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor", "session-read:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "mallory", "Mallory", "mallory-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob := login("alice", "alice-password-123"), login("bob", "bob-password-12345")
	mallory, carol := login("mallory", "mallory-password-1"), login("carol", "carol-password-123")
	aliceID, bobID, malloryID := userIDOf(t, alice), userIDOf(t, bob), userIDOf(t, mallory)

	open := func(t *testing.T) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gw.baseURL, alice, acc, false, "ordinary maintenance window", 30)
		if status != http.StatusCreated || sess == nil {
			t.Fatalf("Alice's session: %d %s", status, body)
		}
		return sess.ID
	}
	read := func(token, id, query string) int {
		code, _, _ := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/"+id+query, token, "")
		return code
	}
	// refusals is what the Audit Service was told about refused reads by `actor` on `id`.
	refusals := func(actor, id string) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		n := 0
		for _, e := range spy.events {
			if e.Action == "session.read" && !e.Success && e.ActorID == actor && e.ResourceID == id {
				n++
			}
		}
		return n
	}
	settle := func() { time.Sleep(400 * time.Millisecond) } // for assertions that something did NOT happen
	s1, s2 := open(t), open(t)

	t.Run("a refused read is on the record, under the name of the one who asked", func(t *testing.T) {
		if code := read(bob, s1, ""); code != http.StatusForbidden {
			t.Fatalf("Bob reading Alice's session: %d, want 403", code)
		}
		spy.waitFor(t, "session.read", s1, false)
		if n := refusals(bobID, s1); n != 1 {
			t.Fatalf("%d event(s) under Bob's name, want 1", n)
		}
		if n := refusals(aliceID, s1); n != 0 {
			t.Fatalf("%d event(s) under the REQUESTER's name: the author of a refusal is the one who was refused", n)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.Action == "session.read" && e.ResourceType != "session" {
				t.Fatalf("the event is about a %q, want a session: %+v", e.ResourceType, e)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the name", func(t *testing.T) {
		forged := "?callerId=" + aliceID + "&actorRoles=platform-admin,auditor"
		if code := read(mallory, s1, forged); code != http.StatusForbidden {
			t.Fatalf("a forged query: %d, want 403", code)
		}
		spy.waitFor(t, "session.read", s1, false)
		if n := refusals(malloryID, s1); n != 1 {
			t.Fatalf("%d event(s) under Mallory's name, want 1 — the verified token's, not the query's", n)
		}
		if n := refusals(aliceID, s1); n != 0 {
			t.Fatalf("the refusal was written under the name the client chose (Alice's)")
		}
	})

	t.Run("a refusal is never softened by the budget, and only the budget reaches the audit", func(t *testing.T) {
		// Mallory has spent one of her three. Ten more refusals, across two sessions: every one
		// is a 403 — the budget decides what is WRITTEN, never what is answered — and the audit
		// holds three in all, because a budget is the user's, not the session's.
		for i := 0; i < 10; i++ {
			id := s1
			if i%2 == 1 {
				id = s2
			}
			if code := read(mallory, id, ""); code != http.StatusForbidden {
				t.Fatalf("refusal %d: %d, want 403 whatever the budget", i, code)
			}
		}
		settle()
		if n := refusals(malloryID, s1) + refusals(malloryID, s2); n != 3 {
			t.Fatalf("%d refusals of Mallory's in the audit out of 11, want 3: the budget bounds what a refusal writes", n)
		}
	})

	t.Run("the budget is each identity's own", func(t *testing.T) {
		// Mallory has spent hers; Bob has spent one of his three.
		if code := read(bob, s2, ""); code != http.StatusForbidden {
			t.Fatalf("Bob: %d, want 403", code)
		}
		spy.waitFor(t, "session.read", s2, false)
		if n := refusals(bobID, s2); n != 1 {
			t.Fatalf("Bob's refusal was not written (%d): Mallory spent her own budget, not his", n)
		}
	})

	t.Run("what is not a refusal writes nothing", func(t *testing.T) {
		before := spy.anyEvent("session.read", false)
		if code := read(alice, s1, ""); code != http.StatusOK {
			t.Fatalf("the requester: %d, want 200", code)
		}
		if code := read(carol, s1, ""); code != http.StatusOK {
			t.Fatalf("Carol (a policy to read on the account): %d, want 200", code)
		}
		if code := read(bob, "sess_0000000000000000", ""); code != http.StatusNotFound {
			t.Fatalf("an unknown session: %d, want 404", code)
		}
		settle()
		if n := spy.anyEvent("session.read", false) - before; n != 0 {
			t.Fatalf("%d event(s) written by reads that were served or did not find a session", n)
		}
		if n := spy.anyEvent("session.read", true); n != 0 {
			t.Fatalf("%d success event(s): a read that is served is not an event", n)
		}
	})

	t.Run("the trail is still whole", func(t *testing.T) {
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: %d", resp.StatusCode)
		}
	})
}

// A budget that is wrong is found at start-up, not on the day somebody is refused — and the
// Broker says the budget it really applies.
func TestSessionReadRefusalConfig_AWrongBudgetStopsTheBroker_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-refusal-config")

	t.Run("a budget must be a number within its bounds: there is no unlimited and no off", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"SESSION_READ_AUDIT_BURST", "0"}, {"SESSION_READ_AUDIT_BURST", "-1"}, {"SESSION_READ_AUDIT_BURST", "1001"},
			{"SESSION_READ_AUDIT_BURST", "abc"}, {"SESSION_READ_AUDIT_BURST", "2.5"}, {"SESSION_READ_AUDIT_BURST", "off"},
			{"SESSION_READ_AUDIT_RATE_PER_MINUTE", "0"}, {"SESSION_READ_AUDIT_RATE_PER_MINUTE", "-3"},
			{"SESSION_READ_AUDIT_RATE_PER_MINUTE", "601"}, {"SESSION_READ_AUDIT_RATE_PER_MINUTE", "unlimited"},
		} {
			out := runUntilExit(t, root, bin, "PORT=18968", c.name+"="+c.value)
			if !strings.Contains(out, c.name) || !strings.Contains(out, "must be a number between") {
				t.Fatalf("%s=%q: expected an error naming the variable and its bounds, got:\n%s", c.name, c.value, out)
			}
		}
	})

	t.Run("the bounds themselves are accepted", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"SESSION_READ_AUDIT_BURST", "1"}, {"SESSION_READ_AUDIT_BURST", "1000"},
			{"SESSION_READ_AUDIT_RATE_PER_MINUTE", "1"}, {"SESSION_READ_AUDIT_RATE_PER_MINUTE", "600"},
		} {
			cmd := execCommandWithEnv(bin, root, []string{"PORT=18969", c.name + "=" + c.value})
			var out syncBuffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, 5*time.Second, "the Broker to be listening with "+c.name+"="+c.value, func() bool {
				return strings.Contains(out.String(), "session-broker listening")
			})
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	})

	t.Run("the Broker says the budget it applies, and says it truly", func(t *testing.T) {
		for _, c := range []struct {
			name, port string
			env        []string
			want       string
		}{
			{"the defaults", "18970", nil, "a burst of 10, then 6 a minute"},
			{"a chosen budget", "18971", []string{"SESSION_READ_AUDIT_BURST=4", "SESSION_READ_AUDIT_RATE_PER_MINUTE=12"}, "a burst of 4, then 12 a minute"},
		} {
			t.Run(c.name, func(t *testing.T) {
				cmd := execCommandWithEnv(bin, root, append([]string{"PORT=" + c.port}, c.env...))
				var out syncBuffer
				cmd.Stdout, cmd.Stderr = &out, &out
				if err := cmd.Start(); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
				waitUntil(t, 5*time.Second, "the Broker to be listening", func() bool {
					return strings.Contains(out.String(), "session-broker listening")
				})
				if !strings.Contains(out.String(), c.want) {
					t.Fatalf("the Broker did not say %q:\n%s", c.want, out.String())
				}
			})
		}
	})
}

package integration_test

// A read that is served to somebody who holds a policy is on the record (ADR-0021), across
// real processes — Authentication, Authorization, Audit (behind a spy that can be made to
// fail), the Session Broker and the Gateway.
//
// Before ADR-0021 a session was read by Carol — a policy holder, the auditor — and nothing
// anywhere said so: the Broker wrote an event for a refusal (ADR-0020) and none for what it
// disclosed. Nobody could prove that an auditor had read a session, nor that nobody else had.
// This is that, written first and seen to fail.
//
// The claims: the read is an event under the name of the one who read — the verified token's,
// whatever the client writes in the query; it is on the record BEFORE the response comes back
// (no waiting for it); every read is one, with no budget to leave one out; the requester's own
// reads are not; and a read that cannot be recorded is not served — the Audit Service down
// makes the auditor's read a 503 that tells nothing of the session, while the requester still
// reads their own session and a refusal is still a refusal.

import (
	"net/http"
	"strings"
	"testing"
)

func TestSessionReadServed_IsOnTheRecordBeforeItIsServed_AndWithoutTheAuditItIsNotServed_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-21")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-21")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-21")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-21")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-21")

	audit := startService(t, root, auditBin, "18981")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "18982")
	authn := startService(t, root, authnBin, "18983", "SKIP_DEMO_SEED=1")
	broker := startService(t, root, brokerBin, "18984",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18986", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18987")
	gw := startService(t, root, gatewayBin, "18985",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:18987",
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")

	const acc = "acc_served_1"
	const justification = "ordinary maintenance window"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor", "session-read:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob, carol := login("alice", "alice-password-123"), login("bob", "bob-password-12345"), login("carol", "carol-password-123")
	aliceID, carolID := userIDOf(t, alice), userIDOf(t, carol)

	status, body, sess := gatewayCreateWith(t, gw.baseURL, alice, acc, false, justification, 30)
	if status != http.StatusCreated || sess == nil {
		t.Fatalf("Alice's session: %d %s", status, body)
	}
	id := sess.ID
	read := func(token, query string) (int, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/"+id+query, token, "")
		return code, text
	}
	// served is what the Audit Service was told about reads that were served on `id` by `actor`.
	served := func(actor string) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		n := 0
		for _, e := range spy.events {
			if e.Action == "session.read" && e.Success && e.ActorID == actor && e.ResourceID == id {
				n++
			}
		}
		return n
	}
	anyServed := func() int { return spy.anyEvent("session.read", true) }

	t.Run("a policy holder's read is on the record, under their name, before the response", func(t *testing.T) {
		if code, text := read(carol, ""); code != http.StatusOK || !strings.Contains(text, justification) {
			t.Fatalf("Carol (a policy to read on the account): %d %s, want 200 and the session", code, text)
		}
		// No waiting: the event is written before the session is handed over.
		if n := served(carolID); n != 1 {
			t.Fatalf("%d event(s) under Carol's name the moment her read was served, want 1", n)
		}
		if n := served(aliceID); n != 0 {
			t.Fatalf("%d event(s) under the REQUESTER's name: the author of a read is the one who read", n)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.Action == "session.read" && e.Success && e.ResourceType != "session" {
				t.Fatalf("the event is about a %q, want a session: %+v", e.ResourceType, e)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the name", func(t *testing.T) {
		forged := "?callerId=" + aliceID + "&actorRoles=platform-admin"
		if code, text := read(carol, forged); code != http.StatusOK {
			t.Fatalf("Carol with a forged query: %d %s, want 200 (she holds the policy)", code, text)
		}
		if n := served(aliceID); n != 0 {
			t.Fatalf("a read was written under the name the client chose (Alice's)")
		}
		if n := served(carolID); n != 2 {
			t.Fatalf("%d event(s) under Carol's name, want 2", n)
		}
	})

	t.Run("every read is an event: there is no budget that leaves one out", func(t *testing.T) {
		for i := 0; i < 15; i++ {
			if code, _ := read(carol, ""); code != http.StatusOK {
				t.Fatalf("read %d: %d, want 200", i, code)
			}
		}
		if n := served(carolID); n != 17 {
			t.Fatalf("%d event(s) for 17 served reads of Carol's, want 17", n)
		}
	})

	t.Run("the requester reading their own session is not an event", func(t *testing.T) {
		before := anyServed()
		for i := 0; i < 3; i++ {
			if code, _ := read(alice, ""); code != http.StatusOK {
				t.Fatalf("the requester: %d, want 200", code)
			}
		}
		if n := anyServed() - before; n != 0 {
			t.Fatalf("%d event(s) for the requester's own reads", n)
		}
	})

	t.Run("a read that cannot be recorded is not served, and tells nothing of the session", func(t *testing.T) {
		before := anyServed()
		spy.setDown(true)
		defer spy.setDown(false)

		code, text := read(carol, "")
		if code != http.StatusServiceUnavailable {
			t.Fatalf("Carol with the audit down: %d %s, want 503", code, text)
		}
		for _, leak := range []string{justification, acc, aliceID, "alice", id} {
			if strings.Contains(text, leak) {
				t.Fatalf("the 503 tells %q of a session that was not served: %q", leak, text)
			}
		}
		// Who does not read through a policy does not depend on the audit.
		if code, _ := read(alice, ""); code != http.StatusOK {
			t.Fatalf("the requester with the audit down: %d, want 200", code)
		}
		// A refusal is still a refusal — best effort, and the same answer.
		if code, _ := read(bob, ""); code != http.StatusForbidden {
			t.Fatalf("a refusal with the audit down: %d, want 403", code)
		}
		if n := anyServed() - before; n != 0 {
			t.Fatalf("%d event(s) recorded while the audit was down", n)
		}
	})

	t.Run("the read goes through, and is on the record, as soon as the audit is back", func(t *testing.T) {
		before := served(carolID)
		if code, text := read(carol, ""); code != http.StatusOK {
			t.Fatalf("Carol with the audit back: %d %s, want 200", code, text)
		}
		if n := served(carolID) - before; n != 1 {
			t.Fatalf("%d event(s) for the read once the audit was back, want 1: the read that was not served must have left none", n)
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

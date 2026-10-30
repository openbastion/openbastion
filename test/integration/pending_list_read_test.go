package integration_test

// A listing of the break-glass requests that wait is on the record before it is served
// (ADR-0023), across real processes — Authentication, Authorization, Audit (behind a spy that
// can be made to fail), the Session Broker and the Gateway.
//
// Before ADR-0023 an approver listed the requests waiting for them (ADR-0012) — who asked, on
// which account, and why, an emergency's justification included — and nothing anywhere said
// so: the same things that are an event when read one by one (ADR-0021) were served without
// any by the list. It was the last read of the Broker left out of the trail. This is that,
// written first and seen to fail.
//
// The claims: each request served in a listing is an event, under the name of the one who
// listed — the verified token's, whatever the client writes in the query; it is on the record
// BEFORE the response comes back; a request that is not on the page served is not one; every
// listing writes again, with no budget; an empty listing discloses nothing and writes nothing;
// and a listing that cannot be recorded is not served — the Audit Service down makes it a 503
// that tells nothing of the requests.

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestPendingListRead_EachRequestServedIsOnTheRecordBeforeItIsServed_AndWithoutTheAuditNoneIs_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-23")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-23")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-23")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-23")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-23")

	audit := startService(t, root, auditBin, "19401")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "19402")
	authn := startService(t, root, authnBin, "19403", "SKIP_DEMO_SEED=1")
	broker := startService(t, root, brokerBin, "19404",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:19406", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:19407", "BREAKGLASS_MAX_MINUTES=30")
	gw := startService(t, root, gatewayBin, "19405",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:19408",
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")

	const acc = "acc_listed_1"
	const reason = "SECRET-JUSTIFICATION recorder down during INC-4242"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "breakglass:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "oncall", "On-call", "oncall-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "oncall2", "On-call 2", "oncall-password-2", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Lead", "bob-password-12345", []string{"lead"})
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"dba"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	oncall, oncall2 := login("oncall", "oncall-password-1"), login("oncall2", "oncall-password-2")
	bob, alice := login("bob", "bob-password-12345"), login("alice", "alice-password-123")
	oncallID, bobID := userIDOf(t, oncall), userIDOf(t, bob)

	request := func(token string) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gw.baseURL, token, acc, true, reason, 10)
		if status != http.StatusCreated || sess.Status != "pending_approval" {
			t.Fatalf("break-glass request: %d %s", status, body)
		}
		return sess.ID
	}
	s1 := request(oncall)

	list := func(token, query string) (int, string, *pendingList) {
		t.Helper()
		code, text := gatewayList(t, gw.baseURL, token, "status=pending_approval"+query)
		var out pendingList
		if code == http.StatusOK {
			if err := json.Unmarshal([]byte(text), &out); err != nil {
				t.Fatalf("list is not JSON: %v: %s", err, text)
			}
		}
		return code, text, &out
	}
	// listed is what the Audit Service was told of `id` served in a listing to `actor`.
	listed := func(actor, id string) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		n := 0
		for _, e := range spy.events {
			if e.Action == "session.listed" && e.Success && e.ActorID == actor && e.ResourceID == id {
				n++
			}
		}
		return n
	}
	anyListed := func() int { return spy.anyEvent("session.listed", true) }

	t.Run("a request served in a listing is on the record, under the lister's name, before the response", func(t *testing.T) {
		code, text, got := list(bob, "")
		if code != http.StatusOK || len(got.Items) != 1 || got.Items[0].Justification != reason {
			t.Fatalf("Bob (approval authority on the account): %d %s, want the request and its justification", code, text)
		}
		// No waiting: the event is written before the listing is handed over.
		if n := listed(bobID, s1); n != 1 {
			t.Fatalf("%d event(s) under Bob's name for %s the moment his listing was served, want 1", n, s1)
		}
		if n := listed(oncallID, s1); n != 0 {
			t.Fatalf("%d event(s) under the REQUESTER's name: the author is the one who listed", n)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.Action == "session.listed" && e.ResourceType != "session" {
				t.Fatalf("the event is about a %q, want a session: %+v", e.ResourceType, e)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the name", func(t *testing.T) {
		code, text, _ := list(bob, "&callerId="+oncallID+"&actorRoles=platform-admin")
		if code != http.StatusOK {
			t.Fatalf("Bob with a forged query: %d %s", code, text)
		}
		if n := listed(oncallID, s1); n != 0 {
			t.Fatalf("a listing was written under the name the client chose")
		}
		if n := listed(bobID, s1); n != 2 {
			t.Fatalf("%d event(s) under Bob's name, want 2", n)
		}
	})

	var s2 string
	t.Run("each request served is one event, every listing writes again, and only what is on the page served", func(t *testing.T) {
		s2 = request(oncall2)
		for i := 0; i < 3; i++ {
			if code, text, got := list(bob, ""); code != http.StatusOK || len(got.Items) != 2 {
				t.Fatalf("listing %d: %d %s, want both requests", i, code, text)
			}
		}
		if a, b := listed(bobID, s1), listed(bobID, s2); a != 5 || b != 3 {
			t.Fatalf("events for %s: %d (want 5), for %s: %d (want 3)", s1, a, s2, b)
		}
		before := anyListed()
		code, text, got := list(bob, "&pageSize=1&page=2")
		if code != http.StatusOK || len(got.Items) != 1 || got.TotalItems != 2 {
			t.Fatalf("page 2 of size 1: %d %s", code, text)
		}
		if n := anyListed() - before; n != 1 || listed(bobID, got.Items[0].ID) == 0 {
			t.Fatalf("%d event(s) for a page of one request, want 1 — for the request on the page", n)
		}
	})

	t.Run("an empty listing discloses nothing and writes nothing", func(t *testing.T) {
		before := anyListed()
		code, text, got := list(alice, "")
		if code != http.StatusOK || len(got.Items) != 0 {
			t.Fatalf("Alice (no authority): %d %s, want an empty list", code, text)
		}
		if n := anyListed() - before; n != 0 {
			t.Fatalf("%d event(s) for an empty listing", n)
		}
	})

	t.Run("a listing that cannot be recorded is not served, and tells nothing of the requests", func(t *testing.T) {
		before := anyListed()
		spy.setDown(true)
		defer spy.setDown(false)

		code, text, _ := list(bob, "")
		if code != http.StatusServiceUnavailable {
			t.Fatalf("Bob with the audit down: %d %s, want 503", code, text)
		}
		for _, leak := range []string{reason, "INC-4242", acc, oncallID, s1, s2} {
			if strings.Contains(text, leak) {
				t.Fatalf("the 503 tells %q of requests that were not served: %q", leak, text)
			}
		}
		// What discloses nothing does not depend on the audit.
		if code, _, _ := list(alice, ""); code != http.StatusOK {
			t.Fatalf("an empty listing with the audit down: %d, want 200", code)
		}
		if n := anyListed() - before; n != 0 {
			t.Fatalf("%d event(s) recorded while the audit was down", n)
		}
	})

	t.Run("the listing is served, and on the record, as soon as the audit is back", func(t *testing.T) {
		a, b := listed(bobID, s1), listed(bobID, s2)
		if code, text, got := list(bob, ""); code != http.StatusOK || len(got.Items) != 2 {
			t.Fatalf("Bob with the audit back: %d %s", code, text)
		}
		if listed(bobID, s1) != a+1 || listed(bobID, s2) != b+1 {
			t.Fatalf("the listing once the audit was back is not one event per request")
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

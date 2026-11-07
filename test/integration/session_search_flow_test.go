package integration_test

// ADR-0080, point 5, across real processes — Gateway, Authentication, Authorization, the Session
// Broker and the Audit Service behind a spy: the search of sessions finds them by their
// justification, among those the caller may read; each session served on the strength of a policy
// is a session.read in the chain before the answer; the requester sees their own and writes
// nothing; the audit down, nothing is served; pages follow one another; the bounds are 400s.

import (
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"testing"
	"time"
)

func TestSessionSearch_ByJustification_OnlyWhatTheCallerMayRead_EachReadRecordedFirst_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-80s")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-80s")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-80s")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-80s")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-80s")

	audit := startService(t, root, auditBin, "19881")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "19882")
	authn := startService(t, root, authnBin, "19883", "SKIP_DEMO_SEED=1")
	playVaultAccounts(t, "19886")
	broker := startService(t, root, brokerBin, "19884",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:19886", "AUDIT_URL="+spy.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:19887")
	gw := startService(t, root, gatewayBin, "19885",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:19887",
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")

	const accRead, accOther = "acc_search_read", "acc_search_other"
	for _, acc := range []string{accRead, accOther} {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+acc, "allow")
	}
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor", "session-read:account:"+accRead, "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, carol := login("alice", "alice-password-123"), login("carol", "carol-password-123")
	carolID := userIDOf(t, carol)

	created := map[string]string{} // id -> account
	for i := 0; i < 3; i++ {
		for _, acc := range []string{accRead, accOther} {
			status, body, sess := gatewayCreateWith(t, gw.baseURL, alice, acc, false, fmt.Sprintf("Incident INC-9001 step %d", i), 30)
			if status != http.StatusCreated || sess == nil {
				t.Fatalf("a session on %s: %d %s", acc, status, body)
			}
			created[sess.ID] = acc
		}
	}
	window := "&from=" + neturl.QueryEscape(time.Now().Add(-time.Hour).UTC().Format(time.RFC3339)) + "&to=" + neturl.QueryEscape(time.Now().Add(time.Minute).UTC().Format(time.RFC3339))
	type page struct {
		Sessions []struct {
			ID                  string `json:"id"`
			PrivilegedAccountID string `json:"privilegedAccountId"`
		} `json:"sessions"`
		Next string `json:"next"`
	}
	search := func(token, query string) (int, page, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/search?"+query, token, "")
		var p page
		_ = json.Unmarshal([]byte(text), &p)
		return code, p, text
	}
	readsBy := func(actor string) map[string]int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		m := map[string]int{}
		for _, e := range spy.events {
			if e.Action == "session.read" && e.Success && e.ActorID == actor {
				m[e.ResourceID]++
			}
		}
		return m
	}

	t.Run("a policy holder finds the sessions of its account by their justification, each a read recorded first", func(t *testing.T) {
		code, p, text := search(carol, "q=inc-9001"+window)
		if code != http.StatusOK || len(p.Sessions) != 3 {
			t.Fatalf("Carol: %d %s, want the 3 sessions of %s", code, text, accRead)
		}
		reads := readsBy(carolID)
		for _, s := range p.Sessions {
			if s.PrivilegedAccountID != accRead {
				t.Fatalf("a session of %s was served to Carol", s.PrivilegedAccountID)
			}
			// No waiting: each read is in the chain the moment the answer is back.
			if reads[s.ID] != 1 {
				t.Fatalf("%s: %d read(s) recorded when the answer came back, want 1", s.ID, reads[s.ID])
			}
		}
	})

	t.Run("the requester sees all of hers without a policy, and nothing is written for her", func(t *testing.T) {
		before := len(readsBy(userIDOf(t, alice)))
		code, p, _ := search(alice, "q=INC-9001"+window)
		if code != http.StatusOK || len(p.Sessions) != 6 || len(readsBy(userIDOf(t, alice))) != before {
			t.Fatalf("Alice: %d, %d session(s), want her 6 and no read written", code, len(p.Sessions))
		}
	})

	t.Run("the audit down: 503, and nothing is served", func(t *testing.T) {
		spy.setDown(true)
		code, p, text := search(carol, "q=inc-9001"+window)
		spy.setDown(false)
		if code != http.StatusServiceUnavailable || len(p.Sessions) != 0 {
			t.Fatalf("the audit down: %d %s", code, text)
		}
	})

	t.Run("out of bounds: 400", func(t *testing.T) {
		long := "&from=" + neturl.QueryEscape(time.Now().Add(-32*24*time.Hour).UTC().Format(time.RFC3339)) + "&to=" + neturl.QueryEscape(time.Now().UTC().Format(time.RFC3339))
		for name, q := range map[string]string{"two characters": "q=in" + window, "32 days": "q=inc" + long, "no window": "q=inc", "a forged cursor": "q=inc&cursor=xyz" + window} {
			if code, _, _ := search(carol, q); code != http.StatusBadRequest {
				t.Fatalf("%s: %d, want 400", name, code)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the caller", func(t *testing.T) {
		code, p, _ := search(carol, "q=inc-9001&callerId="+userIDOf(t, alice)+"&actorRoles=platform-admin"+window)
		if code != http.StatusOK || len(p.Sessions) != 3 {
			t.Fatalf("Carol with a forged query: %d, %d session(s), want her 3", code, len(p.Sessions))
		}
	})
}

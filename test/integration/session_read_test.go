package integration_test

// Who may READ a session (ADR-0019), across real processes — Authentication, Authorization,
// Audit, the Session Broker and the Gateway — and real tokens.
//
// Before ADR-0019 GET /sessions/{id} was relayed as it was and answered to anybody with a
// valid token: the requester, the account, the justification and the deadline of somebody
// else's session. This is the attack, written first and seen to fail.
//
// The claims: the requester reads their own session with no policy; somebody with no right
// is refused — whatever roles or caller the client writes in the query; a policy on
// session-read:account:{id} lets one read the sessions of that account and no other; a
// session that does not exist is a 404; no token is a 401; and a refusal leaks nothing.

import (
	"net/http"
	"strings"
	"testing"
)

func TestSessionRead_OnlyTheRequesterOrAnAuthorisedPersonReadsASession_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-19")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-19")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-19")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-19")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-19")

	audit := startService(t, root, auditBin, "18951")
	authz := startService(t, root, authzBin, "18952")
	authn := startService(t, root, authnBin, "18953", "SKIP_DEMO_SEED=1")
	broker := startService(t, root, brokerBin, "18954",
		"AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL=http://127.0.0.1:18956", "AUDIT_URL="+audit.baseURL,
		"SSH_PROXY_URL=http://127.0.0.1:18957")
	gw := startService(t, root, gatewayBin, "18955",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL, "COMMAND_RECORDER_URL=http://127.0.0.1:18957")

	const acc, other = "acc_read_1", "acc_read_2"
	for _, a := range []string{acc, other} {
		authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "sre", "vault:account:"+a, "allow")
	}
	// Carol may read the sessions of `acc` — and only there. Dave holds the roles that may
	// terminate and approve on it: those are other powers, with other resources.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor", "session-read:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "responder", "session-terminate:account:"+acc, "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "lead", "breakglass-approve:account:"+acc, "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"auditor"})
	authCreateUser(t, authn.baseURL, "dave", "Dave", "dave-password-1234", []string{"responder", "lead"})
	authCreateUser(t, authn.baseURL, "nobody", "Nobody", "nobody-password-12", []string{"nobody"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob := login("alice", "alice-password-123"), login("bob", "bob-password-12345")
	carol, dave := login("carol", "carol-password-123"), login("dave", "dave-password-1234")
	nobody := login("nobody", "nobody-password-12")
	aliceID := userIDOf(t, alice)

	const justification = "ordinary maintenance window for the billing cluster"
	open := func(t *testing.T, onAccount string) string {
		t.Helper()
		status, body, sess := gatewayCreateWith(t, gw.baseURL, alice, onAccount, false, justification, 30)
		if status != http.StatusCreated || sess == nil {
			t.Fatalf("Alice's session: %d %s", status, body)
		}
		return sess.ID
	}
	read := func(token, id, query string) (int, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/"+id+query, token, "")
		return code, text
	}
	s1, s2 := open(t, acc), open(t, other)

	t.Run("the requester reads their own session, with no policy at all", func(t *testing.T) {
		code, text := read(alice, s1, "")
		if code != http.StatusOK || !strings.Contains(text, justification) || !strings.Contains(text, `"active"`) {
			t.Fatalf("Alice reading her own session: %d %s, want 200 with the record", code, text)
		}
	})

	t.Run("somebody who has no right cannot read it — and the refusal tells nothing of it", func(t *testing.T) {
		for name, token := range map[string]string{"Bob (sre, same role as the requester)": bob, "a user with no role that matters": nobody} {
			code, text := read(token, s1, "")
			if code != http.StatusForbidden {
				t.Fatalf("%s read Alice's session: %d %s, want 403", name, code, text)
			}
			for _, leak := range []string{justification, aliceID, acc, "active", "expiresAt"} {
				if strings.Contains(text, leak) {
					t.Fatalf("the refusal to %s says %q: %s", name, leak, text)
				}
			}
		}
	})

	t.Run("what the client writes in the query decides nothing", func(t *testing.T) {
		// Bob claims to be Alice, with the roles of everybody who may read.
		forged := "?callerId=" + aliceID + "&actorRoles=platform-admin,auditor,responder"
		if code, text := read(bob, s1, forged); code != http.StatusForbidden {
			t.Fatalf("a forged query read the session: %d %s, want 403", code, text)
		}
	})

	t.Run("a policy on the account lets one read its sessions — and only that account's", func(t *testing.T) {
		if code, text := read(carol, s1, ""); code != http.StatusOK || !strings.Contains(text, justification) {
			t.Fatalf("Carol (session-read on %s) reading a session there: %d %s, want 200", acc, code, text)
		}
		if code, text := read(carol, s2, ""); code != http.StatusForbidden {
			t.Fatalf("Carol reading a session on another account: %d %s, want 403", code, text)
		}
	})

	t.Run("terminating or approving is not reading: those are other powers", func(t *testing.T) {
		if code, text := read(dave, s1, ""); code != http.StatusForbidden {
			t.Fatalf("Dave (may terminate and approve on %s) read the session: %d %s, want 403", acc, code, text)
		}
	})

	t.Run("an unknown session is a 404 and no token is a 401", func(t *testing.T) {
		if code, text := read(bob, "sess_0000000000000000", ""); code != http.StatusNotFound {
			t.Fatalf("an unknown session: %d %s, want 404", code, text)
		}
		if code, _ := read("", s1, ""); code != http.StatusUnauthorized {
			t.Fatalf("without a token: %d, want 401", code)
		}
	})
}

package integration_test

// A recording that is read is on the record before it is read (ADR-0022), across real
// processes — Authentication, Authorization, Audit (behind a spy that can be made to fail),
// the Command Recorder and the Gateway.
//
// Before ADR-0022 the commands typed in a session were served to anybody holding a policy on
// recording:session:… and nothing anywhere said so: the Command Recorder had no audit client,
// and the Gateway did not even tell it who was reading — only with which roles. It is the most
// sensitive read there is (what was typed, as root, on a production host), and the one ADR-0021
// left out. This is that, written first and seen to fail.
//
// The claims: the read is an event under the name of the one who read — the verified token's,
// whatever the client writes in the query; it is on the record BEFORE the response comes back;
// every page served is one, with no budget to leave one out; a refusal is not a served read;
// and a recording that cannot be recorded as read is not served — the Audit Service down makes
// the auditor's read a 503 that tells nothing of the recording.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRecordingRead_IsOnTheRecordBeforeItIsServed_AndWithoutTheAuditItIsNotServed_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-22")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-22")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-22")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-22")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-22")

	audit := startService(t, root, auditBin, "18991")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "18992")
	authn := startService(t, root, authnBin, "18993", "SKIP_DEMO_SEED=1")
	recorder := startService(t, root, recorderBin, "18994", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+spy.baseURL)
	gw := startService(t, root, gatewayBin, "18995",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:18996", "COMMAND_RECORDER_URL="+recorder.baseURL,
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"session-auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob, carol := login("alice", "alice-password-123"), login("bob", "bob-password-12345"), login("carol", "carol-password-123")
	aliceID, carolID := userIDOf(t, alice), userIDOf(t, carol)

	// What Alice typed in her session, as the proxy would have recorded it. The recorder does
	// not know which sessions exist: this one is a recording and nothing else.
	const id = "sess_recording_read_1"
	commands := []string{"cat /etc/shadow", "mysql -u root prod_customers", "rm -rf /var/log/audit"}
	var batch struct {
		Entries []map[string]any `json:"entries"`
	}
	t0 := time.Now().UTC()
	for i, c := range commands {
		batch.Entries = append(batch.Entries, map[string]any{"session_id": id, "ts": t0.Add(time.Duration(i) * time.Second), "command": c})
	}
	raw, _ := json.Marshal(batch)
	resp, err := http.Post(recorder.baseURL+"/recorder/v1/command-entries", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("recording the session: %d", resp.StatusCode)
	}

	read := func(token, query string) (int, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/"+id+"/recording"+query, token, "")
		return code, text
	}
	// served is what the Audit Service was told about recordings of `id` read by `actor`.
	served := func(actor string) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		n := 0
		for _, e := range spy.events {
			if e.Action == "recording.read" && e.Success && e.ActorID == actor && e.ResourceID == id {
				n++
			}
		}
		return n
	}
	anyServed := func() int { return spy.anyEvent("recording.read", true) }

	t.Run("an auditor's read is on the record, under their name, before the response", func(t *testing.T) {
		code, text := read(carol, "")
		if code != http.StatusOK || !strings.Contains(text, commands[0]) {
			t.Fatalf("Carol (a policy to read recordings): %d %s, want 200 and the commands", code, text)
		}
		// No waiting: the event is written before the recording is handed over.
		if n := served(carolID); n != 1 {
			t.Fatalf("%d event(s) under Carol's name the moment her read was served, want 1", n)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.Action == "recording.read" && e.ResourceType != "session" {
				t.Fatalf("the event is about a %q, want the session the recording is of: %+v", e.ResourceType, e)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the name", func(t *testing.T) {
		forged := "?callerId=" + aliceID + "&actorUserId=" + aliceID + "&actorRoles=platform-admin"
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

	t.Run("every page served is an event: there is no budget that leaves one out", func(t *testing.T) {
		for page := 1; page <= 3; page++ {
			code, text := read(carol, "?pageSize=1&page="+string(rune('0'+page)))
			if code != http.StatusOK || !strings.Contains(text, commands[page-1]) {
				t.Fatalf("page %d: %d %s", page, code, text)
			}
		}
		for i := 0; i < 12; i++ {
			if code, _ := read(carol, ""); code != http.StatusOK {
				t.Fatalf("read %d: %d, want 200", i, code)
			}
		}
		if n := served(carolID); n != 17 {
			t.Fatalf("%d event(s) for 17 served reads of Carol's, want 17", n)
		}
	})

	t.Run("a refusal is not a served read, and serves nothing", func(t *testing.T) {
		before := anyServed()
		code, text := read(bob, "")
		if code != http.StatusForbidden {
			t.Fatalf("Bob (no policy): %d %s, want 403", code, text)
		}
		for _, c := range commands {
			if strings.Contains(text, c) {
				t.Fatalf("a refusal tells %q", c)
			}
		}
		if n := anyServed() - before; n != 0 {
			t.Fatalf("%d served-read event(s) for a refusal", n)
		}
	})

	t.Run("a recording that cannot be recorded as read is not served, and tells nothing of it", func(t *testing.T) {
		before := anyServed()
		spy.setDown(true)
		defer spy.setDown(false)

		code, text := read(carol, "")
		if code != http.StatusServiceUnavailable {
			t.Fatalf("Carol with the audit down: %d %s, want 503", code, text)
		}
		for _, leak := range append([]string{id, "totalEntries", "emit-event", spy.baseURL}, commands...) {
			if strings.Contains(text, leak) {
				t.Fatalf("the 503 tells %q of a recording that was not served: %q", leak, text)
			}
		}
		// A refusal is still a refusal.
		if code, _ := read(bob, ""); code != http.StatusForbidden {
			t.Fatalf("a refusal with the audit down: %d, want 403", code)
		}
		if n := anyServed() - before; n != 0 {
			t.Fatalf("%d event(s) recorded while the audit was down", n)
		}
	})

	t.Run("the read goes through, and is on the record, as soon as the audit is back", func(t *testing.T) {
		before := served(carolID)
		if code, text := read(carol, ""); code != http.StatusOK || !strings.Contains(text, commands[2]) {
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

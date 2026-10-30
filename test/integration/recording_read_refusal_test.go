package integration_test

// A refused read of a recording is on the record, under the name of the one who asked, within
// a budget per identity (ADR-0024), across real processes — Authentication, Authorization,
// Audit (behind a spy that can be made to fail), the Command Recorder and the Gateway.
//
// Before ADR-0024 somebody without a policy could try recording after recording — what was
// typed in each session, as root — and be refused each time with nothing anywhere saying so:
// ADR-0022 wrote a served read, and nothing for a refusal. This is that, written first and seen
// to fail, with the bound that keeps a refusal from being a way to write into the trail at will.

import (
	"bytes"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestRecordingReadRefusal_IsOnTheRecordUnderTheNameOfWhoAsked_WithinABudget_AcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-24")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-24")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-24")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-24")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-24")

	audit := startService(t, root, auditBin, "19411")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "19412")
	authn := startService(t, root, authnBin, "19413", "SKIP_DEMO_SEED=1")
	// A small budget, so that it is reached: 3 at once, then one a minute.
	recorder := startService(t, root, recorderBin, "19414", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+spy.baseURL,
		"RECORDING_READ_AUDIT_BURST=3", "RECORDING_READ_AUDIT_RATE_PER_MINUTE=1")
	gw := startService(t, root, gatewayBin, "19415",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:19416", "COMMAND_RECORDER_URL="+recorder.baseURL,
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")
	authCreateUser(t, authn.baseURL, "alice", "Alice", "alice-password-123", []string{"sre"})
	authCreateUser(t, authn.baseURL, "bob", "Bob", "bob-password-12345", []string{"sre"})
	authCreateUser(t, authn.baseURL, "mallory", "Mallory", "mallory-password-1", []string{"sre"})
	authCreateUser(t, authn.baseURL, "carol", "Carol", "carol-password-123", []string{"session-auditor"})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	alice, bob := login("alice", "alice-password-123"), login("bob", "bob-password-12345")
	mallory, carol := login("mallory", "mallory-password-1"), login("carol", "carol-password-123")
	aliceID, bobID, malloryID, carolID := userIDOf(t, alice), userIDOf(t, bob), userIDOf(t, mallory), userIDOf(t, carol)

	const id, other = "sess_recording_refusal_1", "sess_recording_refusal_2"
	raw, _ := json.Marshal(map[string]any{"entries": []map[string]any{
		{"session_id": id, "ts": time.Now().UTC(), "command": "cat /etc/shadow"},
		{"session_id": other, "ts": time.Now().UTC(), "command": "psql prod"},
	}})
	resp, err := http.Post(recorder.baseURL+"/recorder/v1/command-entries", "application/json", bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusAccepted {
		t.Fatalf("recording: %d", resp.StatusCode)
	}

	read := func(token, sessionID, query string) (int, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/sessions/"+sessionID+"/recording"+query, token, "")
		return code, text
	}
	// refused counts the refusals the Audit Service was told of, by actor (any session).
	refused := func(actor string) int {
		spy.mu.Lock()
		defer spy.mu.Unlock()
		n := 0
		for _, e := range spy.events {
			if e.Action == "recording.read" && !e.Success && e.ActorID == actor {
				n++
			}
		}
		return n
	}
	settle := func() { time.Sleep(300 * time.Millisecond) } // for assertions that something did NOT happen

	var refusalBody string
	t.Run("a refusal is on the record, under the name of who asked, about the session asked for", func(t *testing.T) {
		code, text := read(bob, id, "")
		if code != http.StatusForbidden || strings.Contains(text, "cat /etc/shadow") {
			t.Fatalf("Bob (no policy): %d %s, want 403 and nothing of the recording", code, text)
		}
		refusalBody = text
		if n := refused(bobID); n != 1 {
			t.Fatalf("%d refusal(s) under Bob's name, want 1", n)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.Action == "recording.read" && !e.Success && (e.ResourceType != "session" || e.ResourceID != id) {
				t.Fatalf("the refusal is about %s %q, want the session %q: %+v", e.ResourceType, e.ResourceID, id, e)
			}
		}
	})

	t.Run("what the client writes in the query does not choose the name", func(t *testing.T) {
		if code, _ := read(bob, id, "?callerId="+aliceID+"&actorRoles=session-auditor"); code != http.StatusForbidden {
			t.Fatalf("Bob with a forged query: %d, want 403", code)
		}
		if n := refused(aliceID); n != 0 {
			t.Fatalf("a refusal was written under the name the client chose (Alice's)")
		}
		if n := refused(bobID); n != 2 {
			t.Fatalf("%d refusal(s) under Bob's name, want 2", n)
		}
	})

	t.Run("the budget is the identity's: eleven refusals over two sessions, all 403, three written", func(t *testing.T) {
		for i := 0; i < 11; i++ {
			sessionID := id
			if i%2 == 1 {
				sessionID = other
			}
			code, text := read(mallory, sessionID, "")
			if code != http.StatusForbidden || text != refusalBody {
				t.Fatalf("refusal %d: %d %q, want the same 403 as any refusal (%q)", i, code, text, refusalBody)
			}
		}
		settle()
		if n := refused(malloryID); n != 3 {
			t.Fatalf("%d refusal(s) of Mallory's written, want the burst of 3", n)
		}
		// Bob's budget was not touched by Mallory's: he had one token left of three.
		if code, _ := read(bob, id, ""); code != http.StatusForbidden {
			t.Fatalf("Bob: %d", code)
		}
		if n := refused(bobID); n != 3 {
			t.Fatalf("%d refusal(s) under Bob's name, want 3: his budget is his own", n)
		}
	})

	t.Run("a served read is not a refusal and spends nothing of the budget", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			if code, _ := read(carol, id, ""); code != http.StatusOK {
				t.Fatalf("Carol: %d, want 200", code)
			}
		}
		if n := refused(carolID); n != 0 {
			t.Fatalf("%d refusal(s) for served reads", n)
		}
		if n := spy.anyEvent("recording.read", true); n != 5 {
			t.Fatalf("%d served read(s) on the record, want 5 (ADR-0022, whatever the refusal budget)", n)
		}
	})

	t.Run("with the audit down a refusal is still the same refusal", func(t *testing.T) {
		spy.setDown(true)
		defer spy.setDown(false)
		code, text := read(alice, id, "")
		if code != http.StatusForbidden || text != refusalBody {
			t.Fatalf("a refusal with the audit down: %d %q, want the same 403 (%q)", code, text, refusalBody)
		}
	})

	t.Run("what cannot be a session is refused before anything, and writes nothing", func(t *testing.T) {
		before := spy.anyEvent("recording.read", false) + spy.anyEvent("recording.read", true)
		long := strings.Repeat("x", 257)
		for _, token := range []string{alice, carol} {
			if code, text := read(token, long, ""); code != http.StatusBadRequest {
				t.Fatalf("a 257-byte session id: %d %s, want 400", code, text)
			}
		}
		settle()
		if n := spy.anyEvent("recording.read", false) + spy.anyEvent("recording.read", true) - before; n != 0 {
			t.Fatalf("%d event(s) for a session id that cannot be one", n)
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
// Recorder says the budget it really applies.
func TestRecordingReadRefusalConfig_AWrongBudgetStopsTheRecorder_AndWhatIsSaidAtStartIsTrue(t *testing.T) {
	root := repoRoot(t)
	bin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-refusal-config")

	t.Run("a budget must be a number within its bounds: there is no unlimited and no off", func(t *testing.T) {
		for _, c := range []struct{ name, value string }{
			{"RECORDING_READ_AUDIT_BURST", "0"}, {"RECORDING_READ_AUDIT_BURST", "-1"}, {"RECORDING_READ_AUDIT_BURST", "1001"},
			{"RECORDING_READ_AUDIT_BURST", "abc"}, {"RECORDING_READ_AUDIT_BURST", "2.5"}, {"RECORDING_READ_AUDIT_BURST", "off"},
			{"RECORDING_READ_AUDIT_RATE_PER_MINUTE", "0"}, {"RECORDING_READ_AUDIT_RATE_PER_MINUTE", "-3"},
			{"RECORDING_READ_AUDIT_RATE_PER_MINUTE", "601"}, {"RECORDING_READ_AUDIT_RATE_PER_MINUTE", "unlimited"},
		} {
			out := runUntilExit(t, root, bin, "PORT=19417", c.name+"="+c.value)
			if !strings.Contains(out, c.name) || !strings.Contains(out, "must be a number between") {
				t.Fatalf("%s=%q: expected an error naming the variable and its bounds, got:\n%s", c.name, c.value, out)
			}
		}
	})

	t.Run("the bounds are accepted, and the Recorder says the budget it applies", func(t *testing.T) {
		for _, c := range []struct {
			env  []string
			want string
		}{
			{nil, "a burst of 10, then 6 a minute"},
			{[]string{"RECORDING_READ_AUDIT_BURST=1", "RECORDING_READ_AUDIT_RATE_PER_MINUTE=600"}, "a burst of 1, then 600 a minute"},
			{[]string{"RECORDING_READ_AUDIT_BURST=1000", "RECORDING_READ_AUDIT_RATE_PER_MINUTE=1"}, "a burst of 1000, then 1 a minute"},
		} {
			cmd := execCommandWithEnv(bin, root, append([]string{"PORT=19418"}, c.env...))
			var out syncBuffer
			cmd.Stdout, cmd.Stderr = &out, &out
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			waitUntil(t, 5*time.Second, "the Recorder to be listening", func() bool {
				return strings.Contains(out.String(), "command-recorder listening")
			})
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
			if !strings.Contains(out.String(), c.want) {
				t.Fatalf("%v: the Recorder did not say %q:\n%s", c.env, c.want, out.String())
			}
		}
	})
}

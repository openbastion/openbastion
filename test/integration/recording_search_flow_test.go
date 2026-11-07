package integration_test

// ADR-0080 across real processes, under PostgreSQL and a real Audit Service (behind a spy): the
// search of recorded commands decrypts on the fly. It finds a substring without case in the
// sessions the caller may read, and only those; the search is written before anything is
// decrypted, with a digest of the text and never the text; each session the answer discloses is
// a recording.read; the audit down, nothing is served; the text of a command is in no table in
// clear afterwards. The commands are recorded as the SSH proxy records them, through the
// Recorder's route: no SSH session is typed here.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"strings"
	"testing"
	"time"
)

func TestRecordingSearch_DecryptsOnTheFly_OnlyWhatTheCallerMayRead_AuditedFirst(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-80")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-80")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-80")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-80")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-80")

	audit := startService(t, root, auditBin, "19861")
	spy := startAuditSpy(t, audit.baseURL)
	authz := startService(t, root, authzBin, "19862")
	authn := startService(t, root, authnBin, "19863", "SKIP_DEMO_SEED=1")
	// Only this test's sessions in the window: the database is shared with tests whose recordings
	// are sealed under other keys.
	started := time.Now().Add(-time.Second)
	kms := testKMSKeyHex(t)
	conf := t.TempDir()
	key := writeFile(t, conf, "search-key", strings.Repeat("5a", 32)+"\n", 0o600)
	recorder := startService(t, root, recorderBin, "19864", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+spy.baseURL,
		"DATABASE_URL="+dsn, "KMS_KEY_HEX="+kms, "SEARCH_AUDIT_KEY_FILE="+key)
	gw := startService(t, root, gatewayBin, "19865",
		"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:19866", "COMMAND_RECORDER_URL="+recorder.baseURL,
		"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")
	if !strings.Contains(recorder.out.String(), "the search of recordings is on") {
		t.Fatalf("the start does not say the search is on:\n%s", recorder.out.String())
	}

	run := fmt.Sprint(time.Now().UnixNano())
	sessA, sessB := "sess_search_a_"+run, "sess_search_b_"+run
	secret := "Pw-" + run
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor-all-"+run, "recording:session:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "auditor-a-"+run, "recording:session:"+sessA, "allow")
	authCreateUser(t, authn.baseURL, "carol-"+run, "Carol", "carol-password-123", []string{"auditor-all-" + run})
	authCreateUser(t, authn.baseURL, "dave-"+run, "Dave", "dave-password-1234", []string{"auditor-a-" + run})
	login := func(user, pw string) string {
		tok, status := gatewayLogin(t, gw.baseURL, user, pw)
		if status != http.StatusOK {
			t.Fatalf("login %s: %d", user, status)
		}
		return tok
	}
	carol, dave := login("carol-"+run, "carol-password-123"), login("dave-"+run, "dave-password-1234")
	carolID := userIDOf(t, carol)

	record := func(session string, commands ...string) {
		var batch struct {
			Entries []map[string]any `json:"entries"`
		}
		t0 := time.Now().UTC()
		for i, c := range commands {
			batch.Entries = append(batch.Entries, map[string]any{"session_id": session, "ts": t0.Add(time.Duration(i) * time.Second), "command": c})
		}
		raw, _ := json.Marshal(batch)
		resp, err := http.Post(recorder.baseURL+"/recorder/v1/command-entries", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("recording %s: %d", session, resp.StatusCode)
		}
	}
	record(sessA, "ls -la", "sudo cat /etc/shadow", "mysql -u root -p'"+secret+"' prod")
	record(sessB, "cat /etc/shadow > /tmp/x")

	window := func(from, to time.Time) string {
		return "&from=" + neturl.QueryEscape(from.UTC().Format(time.RFC3339)) + "&to=" + neturl.QueryEscape(to.UTC().Format(time.RFC3339))
	}
	now := time.Now()
	last := window(started, now.Add(time.Minute))
	type answer struct {
		SearchID string `json:"searchId"`
		Sessions []struct {
			SessionID string `json:"sessionId"`
			Hits      []struct {
				Command string `json:"command"`
			} `json:"hits"`
		} `json:"sessions"`
		Truncated bool `json:"truncated"`
	}
	search := func(token, q, w string) (int, answer, string) {
		code, _, text := rawRequest(t, http.MethodGet, gw.baseURL+"/recordings/search?q="+neturl.QueryEscape(q)+w, token, "")
		var a answer
		_ = json.Unmarshal([]byte(text), &a)
		return code, a, text
	}
	found := func(a answer) map[string]int {
		m := map[string]int{}
		for _, s := range a.Sessions {
			m[s.SessionID] = len(s.Hits)
		}
		return m
	}

	t.Run("a substring without case, in every session the caller may read", func(t *testing.T) {
		code, a, text := search(carol, "CAT /ETC/SHADOW", last)
		if code != http.StatusOK || found(a)[sessA] != 1 || found(a)[sessB] != 1 {
			t.Fatalf("Carol: %d %s, want one hit in each session", code, text)
		}
		var ev *spiedEvent
		spy.mu.Lock()
		for i := range spy.events {
			if e := spy.events[i]; e.Action == "recording.search" && e.ResourceID == a.SearchID {
				ev = &spy.events[i]
			}
		}
		spy.mu.Unlock()
		if ev == nil || ev.ActorID != carolID || ev.Details["q_hmac"] == "" || ev.Details["allowed"] == "" {
			t.Fatalf("recording.search: %+v", ev)
		}
		for _, s := range []string{sessA, sessB} {
			if spy.detailsOf("recording.read", s)["search_id"] != a.SearchID {
				t.Fatalf("no recording.read of %s tied to the search", s)
			}
		}
	})

	t.Run("a caller with a policy on one session finds only that one", func(t *testing.T) {
		code, a, text := search(dave, "cat /etc/shadow", last)
		if code != http.StatusOK || found(a)[sessA] != 1 || found(a)[sessB] != 0 {
			t.Fatalf("Dave: %d %s, want %s only", code, text, sessA)
		}
	})

	t.Run("the text searched is in no audit event and in no log", func(t *testing.T) {
		code, a, _ := search(carol, secret, last)
		if code != http.StatusOK || found(a)[sessA] != 1 {
			t.Fatalf("the secret, searched: %d %+v", code, a)
		}
		spy.mu.Lock()
		raw, _ := json.Marshal(spy.events)
		spy.mu.Unlock()
		if strings.Contains(string(raw), secret) {
			t.Fatal("the text searched is in an audit event")
		}
		for name, out := range map[string]string{"recorder": recorder.out.String(), "gateway": gw.out.String()} {
			if strings.Contains(out, secret) {
				t.Fatalf("the text searched is in the %s's log", name)
			}
		}
	})

	t.Run("the audit down: 503, and nothing is served", func(t *testing.T) {
		spy.setDown(true)
		code, _, text := search(carol, "shadow", last)
		spy.setDown(false)
		if code != http.StatusServiceUnavailable || strings.Contains(text, "shadow") {
			t.Fatalf("the audit down: %d %s, want 503 and nothing of the recordings", code, text)
		}
	})

	t.Run("out of bounds: 400", func(t *testing.T) {
		if code, _, _ := search(carol, "ls", last); code != http.StatusBadRequest {
			t.Fatalf("two characters: %d", code)
		}
		if code, _, _ := search(carol, "shadow", window(now.Add(-32*24*time.Hour), now)); code != http.StatusBadRequest {
			t.Fatalf("32 days: %d", code)
		}
		if code, _, _ := search(carol, "shadow", ""); code != http.StatusBadRequest {
			t.Fatalf("no window: %d", code)
		}
	})

	t.Run("no command is in clear in any table of the Recorder", func(t *testing.T) {
		rows, err := db.Query(`SELECT table_name, column_name FROM information_schema.columns
			WHERE table_schema = 'public' AND data_type IN ('text', 'character varying', 'bytea', 'jsonb')`)
		if err != nil {
			t.Fatal(err)
		}
		type col struct{ table, column string }
		var cols []col
		for rows.Next() {
			var c col
			_ = rows.Scan(&c.table, &c.column)
			cols = append(cols, c)
		}
		rows.Close()
		read := map[string]bool{}
		for _, c := range cols {
			var n int
			q := fmt.Sprintf(`SELECT count(*) FROM %q WHERE position(convert_to($1, 'UTF8') in convert_to(%q::text, 'UTF8')) > 0`, c.table, c.column)
			if err := db.QueryRow(q, secret).Scan(&n); err != nil {
				continue // a column that cannot be read as text
			}
			if n > 0 {
				t.Fatalf("the command is in clear in %s.%s", c.table, c.column)
			}
			read[c.table+"."+c.column] = true
		}
		// The check read the table that holds the commands: it is not vacuous.
		if !read["session_command_entries.command_sealed"] {
			t.Fatalf("the command table was not read: %v", read)
		}
	})

	t.Run("without its key the search is off: 404", func(t *testing.T) {
		stopService(t, gw)
		stopService(t, recorder)
		off := startService(t, root, recorderBin, "19867", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+spy.baseURL,
			"DATABASE_URL="+dsn, "KMS_KEY_HEX="+kms)
		gw2 := startService(t, root, gatewayBin, "19868",
			"AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL=http://127.0.0.1:19866", "COMMAND_RECORDER_URL="+off.baseURL,
			"CLIENT_REQUEST_BURST=500", "CLIENT_REQUEST_RATE_PER_MINUTE=600")
		code, _, _ := rawRequest(t, http.MethodGet, gw2.baseURL+"/recordings/search?q=shadow"+last, carol, "")
		if code != http.StatusNotFound {
			t.Fatalf("no key: %d, want 404", code)
		}
	})
}

// ADR-0080: a search at the bound of 200 sessions, each key unwrapped by a real Transit (ADR-0049).
// The time is what this test reports; it fails only past a generous bound.
func TestRecordingSearch_AtTheBoundOf200Sessions_WithRealTransit_IsMeasured(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	bao, tokenFile := startOpenBao(t, "openbastion-vault")
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-80t")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-80t")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-80t")
	audit := startService(t, root, auditBin, "19871")
	authz := startService(t, root, authzBin, "19872")
	key := writeFile(t, t.TempDir(), "search-key", strings.Repeat("6b", 32), 0o600)
	started := time.Now().Add(-time.Second)
	recorder := startService(t, root, recorderBin, "19873", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL, "DATABASE_URL="+dsn,
		"TRANSIT_ADDR="+bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE="+tokenFile, "SEARCH_AUDIT_KEY_FILE="+key)
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "measure-auditor", "recording:session:*", "allow")

	run := fmt.Sprint(time.Now().UnixNano())
	for s := 0; s < 200; s++ {
		var batch struct {
			Entries []map[string]any `json:"entries"`
		}
		t0 := time.Now().UTC()
		for i := 0; i < 50; i++ {
			c := fmt.Sprintf("sudo systemctl restart nginx --unit-%d && tail -n 200 /var/log/nginx/error.log", i)
			if s%20 == 0 && i == 7 {
				c = "cat /etc/shadow"
			}
			batch.Entries = append(batch.Entries, map[string]any{"session_id": fmt.Sprintf("sess_measure_%s_%03d", run, s), "ts": t0.Add(time.Duration(i) * time.Millisecond), "command": c})
		}
		raw, _ := json.Marshal(batch)
		resp, err := http.Post(recorder.baseURL+"/recorder/v1/command-entries", "application/json", bytes.NewReader(raw))
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusAccepted {
			t.Fatalf("recording session %d: %d", s, resp.StatusCode)
		}
	}
	q := neturl.Values{"q": {"/etc/shadow"}, "from": {started.UTC().Format(time.RFC3339)}, "to": {time.Now().Add(time.Minute).UTC().Format(time.RFC3339)},
		"callerId": {"u_measure"}, "actorRoles": {"measure-auditor"}}
	begin := time.Now()
	resp, err := http.Get(recorder.baseURL + "/recorder/v1/search?" + q.Encode())
	elapsed := time.Since(begin)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var a struct {
		Sessions  []json.RawMessage `json:"sessions"`
		Truncated bool              `json:"truncated"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&a)
	if resp.StatusCode != http.StatusOK || len(a.Sessions) != 10 || a.Truncated {
		t.Fatalf("search: %d, %d session(s) found, truncated=%v; want 200, 10, false", resp.StatusCode, len(a.Sessions), a.Truncated)
	}
	t.Logf("MEASURED: a search of 200 sessions × 50 commands, each key unwrapped by Transit: %v", elapsed.Round(time.Millisecond))
	if elapsed > time.Minute {
		t.Fatalf("a search at the bound took %v", elapsed)
	}
}

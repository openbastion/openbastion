package integration_test

// Archiving the audit chain out of the database without making it unverifiable (ADR-0032), on
// a real Audit Service against a real PostgreSQL.
//
// Before ADR-0032 nothing ever left audit_events: a retention could only be a deletion, and a
// deletion made the chain unverifiable. The claim: the months older than the retention are
// archived, checkpointed with the anchors and deleted; after a process restart, historical
// secret-injection outcomes remain reconcilable from those archives, and chain cuts or removed
// checkpoints are still found.

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_OldMonthsAreArchivedOutOfTheDatabase_AndArchivedInjectionsSurviveRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	run := func(t *testing.T, q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-32")
	key := testKMSKeyHex(t)

	t.Run("retention needs both variables, bounded months, a directory and the anchors", func(t *testing.T) {
		dir := t.TempDir()
		anchors := t.TempDir() + "/anchors.jsonl"
		base := []string{"PORT=19473", "DATABASE_URL=" + dsn, "AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_ANCHOR_FILE=" + anchors}
		for _, env := range [][]string{
			{"AUDIT_ARCHIVE_DIR=" + dir},
			{"AUDIT_RETENTION_MONTHS=12"},
			{"AUDIT_ARCHIVE_DIR=" + dir, "AUDIT_RETENTION_MONTHS=0"},
			{"AUDIT_ARCHIVE_DIR=" + dir, "AUDIT_RETENTION_MONTHS=121"},
			{"AUDIT_ARCHIVE_DIR=" + dir, "AUDIT_RETENTION_MONTHS=forever"},
			{"AUDIT_ARCHIVE_DIR=archives", "AUDIT_RETENTION_MONTHS=12"},
			{"AUDIT_ARCHIVE_DIR=/nonexistent-dir-for-openbastion", "AUDIT_RETENTION_MONTHS=12"},
		} {
			out := runUntilExit(t, root, auditBin, append(base, env...)...)
			if !strings.Contains(out, "AUDIT_ARCHIVE_DIR") && !strings.Contains(out, "AUDIT_RETENTION_MONTHS") {
				t.Fatalf("%v: expected a refusal naming the variable, got:\n%s", env, out)
			}
		}
		// In memory, archiving without the anchors is refused too: the checkpoints live there.
		out := runUntilExit(t, root, auditBin, "PORT=19473", "AUDIT_ARCHIVE_DIR="+dir, "AUDIT_RETENTION_MONTHS=12")
		if !strings.Contains(out, "needs AUDIT_ANCHOR_FILE") {
			t.Fatalf("archiving without anchors: %s", out)
		}
	})

	// Apply the real Audit Service migrations first so this test also works against a fresh
	// PostgreSQL 16 database, rather than relying on another integration test to create tables.
	schemaAnchors := filepath.Join(t.TempDir(), "schema-anchors.jsonl")
	schemaService := startService(t, root, auditBin, "19470", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key, "AUDIT_ANCHOR_FILE="+schemaAnchors)
	stopService(t, schemaService)

	// Seed a valid keyed-v4 chain in January and February 2025. Two historical injections
	// (start + terminal) must be found in their archives after the Audit Service restarts.
	truncateAuditEvents(t, db)
	t.Cleanup(func() { truncateAuditEvents(t, db) })
	chainKey, err := hex.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	var prev []byte
	prev = insertAuditV4Event(t, db, chainKey, prev, "evt_jan_start", time.Date(2025, 1, 3, 9, 0, 0, 0, time.UTC), "user_a", "session.secret_injection_started", "session", "sess_archived_jan", "ssh-proxy", map[string]string{
		"injection_id": "0123456789abcdef0123456789abcdef", "account_id": "acc_archived_jan", "protocol": "ssh",
	}, true)
	prev = insertAuditV4Event(t, db, chainKey, prev, "evt_jan_done", time.Date(2025, 1, 4, 9, 0, 0, 0, time.UTC), "user_a", "session.secret_injected", "session", "sess_archived_jan", "ssh-proxy", map[string]string{
		"injection_id": "0123456789abcdef0123456789abcdef", "account_id": "acc_archived_jan", "protocol": "ssh",
	}, true)
	prev = insertAuditV4Event(t, db, chainKey, prev, "evt_jan_other", time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC), "user_a", "session.connect", "session", "session_old", "session-broker", nil, true)
	prev = insertAuditV4Event(t, db, chainKey, prev, "evt_feb_start", time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), "user_a", "session.secret_injection_started", "session", "sess_archived_feb", "ssh-proxy", map[string]string{
		"injection_id": "fedcba9876543210fedcba9876543210", "account_id": "acc_archived_feb", "protocol": "vnc",
	}, true)
	_ = insertAuditV4Event(t, db, chainKey, prev, "evt_feb_done", time.Date(2025, 2, 27, 9, 0, 0, 0, time.UTC), "user_a", "session.secret_injected", "session", "sess_archived_feb", "ssh-proxy", map[string]string{
		"injection_id": "fedcba9876543210fedcba9876543210", "account_id": "acc_archived_feb", "protocol": "vnc",
	}, true)

	archives := t.TempDir()
	anchors := t.TempDir() + "/anchors.jsonl"
	audit := startService(t, root, auditBin, "19471", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key,
		"AUDIT_ANCHOR_FILE="+anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=1",
		"AUDIT_ARCHIVE_DIR="+archives, "AUDIT_RETENTION_MONTHS=1")
	waitUntil(t, 10*time.Second, "January and February 2025 archived", func() bool {
		_, err1 := os.Stat(filepath.Join(archives, "audit-2025-01.jsonl"))
		_, err2 := os.Stat(filepath.Join(archives, "audit-2025-02.jsonl"))
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE ts < '2025-03-01'`).Scan(&n)
		return err1 == nil && err2 == nil && n == 0
	})
	verify := func(t *testing.T) (int, string) {
		t.Helper()
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		b := make([]byte, 600)
		n, _ := resp.Body.Read(b)
		return resp.StatusCode, string(b[:n])
	}

	t.Run("the archives hold the months, the database the rest, and the chain left verifies", func(t *testing.T) {
		for name, want := range map[string]int{"audit-2025-01.jsonl": 3, "audit-2025-02.jsonl": 2} {
			raw, err := os.ReadFile(filepath.Join(archives, name))
			if err != nil {
				t.Fatal(err)
			}
			if n := strings.Count(string(raw), "\n"); n != want {
				t.Fatalf("%s holds %d events, want %d", name, n, want)
			}
		}
		var archived int
		_ = db.QueryRow(`SELECT count(*) FROM audit_events WHERE action = 'audit.archived' AND emitter = 'audit-service' AND resource_type = 'audit'`).Scan(&archived)
		if archived != 2 {
			t.Fatalf("%d archiving events in the chain, want 2", archived)
		}
		if code, text := verify(t); code != http.StatusOK {
			t.Fatalf("verify-chain after archiving: %d %s", code, text)
		}
		if !strings.Contains(audit.out.String(), "archived audit-2025-01.jsonl") {
			t.Fatalf("the archiving is not in the log:\n%s", audit.out.String())
		}
	})

	testT := t // The restarted service must live until all later tamper subtests have finished.
	reconcile := func(t *testing.T) reconciliationResponse {
		t.Helper()
		resp, err := http.Get(audit.baseURL + "/audit/v1/secret-injections?limit=50")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("secret-injection reconciliation: %d %s", resp.StatusCode, raw)
		}
		var page reconciliationResponse
		if err := json.Unmarshal(raw, &page); err != nil {
			t.Fatalf("decode secret-injection reconciliation: %v (%s)", err, raw)
		}
		return page
	}

	t.Run("archived injection evidence survives an Audit Service restart", func(t *testing.T) {
		assertArchivedInjections(t, reconcile(t))
		stopService(t, audit)
		audit = startService(testT, root, auditBin, "19471", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key,
			"AUDIT_ANCHOR_FILE="+anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=1",
			"AUDIT_ARCHIVE_DIR="+archives, "AUDIT_RETENTION_MONTHS=1")
		if code, text := verify(t); code != http.StatusOK {
			t.Fatalf("verify-chain after process restart: %d %s", code, text)
		}
		assertArchivedInjections(t, reconcile(t))
	})

	t.Run("the start of the chain cut past the checkpoint is found", func(t *testing.T) {
		run(t, `DROP TABLE IF EXISTS audit_retention_snapshot`)
		run(t, `CREATE TABLE audit_retention_snapshot AS SELECT * FROM audit_events`)
		t.Cleanup(func() { _, _ = db.Exec(`DROP TABLE IF EXISTS audit_retention_snapshot`) })
		run(t, `DELETE FROM audit_events WHERE seq = (SELECT min(seq) FROM audit_events)`)
		if code, text := verify(t); code != http.StatusConflict {
			t.Fatalf("the first event left deleted: verify-chain %d %q, want 409", code, text)
		}
		run(t, `DELETE FROM audit_events`)
		run(t, `INSERT INTO audit_events SELECT * FROM audit_retention_snapshot`)
		if code, text := verify(t); code != http.StatusOK {
			t.Fatalf("restored: %d %s", code, text)
		}
	})

	t.Run("a checkpoint taken out of the anchor file is found", func(t *testing.T) {
		raw, err := os.ReadFile(anchors)
		if err != nil {
			t.Fatal(err)
		}
		var kept []string
		sc := bufio.NewScanner(strings.NewReader(string(raw)))
		dropped := false
		for sc.Scan() {
			if !dropped && strings.Contains(sc.Text(), `"kind":"checkpoint"`) && strings.Contains(sc.Text(), "audit-2025-02") {
				dropped = true
				continue
			}
			kept = append(kept, sc.Text())
		}
		if !dropped {
			t.Fatalf("no checkpoint of February in the anchor file:\n%s", raw)
		}
		if err := os.WriteFile(anchors, []byte(strings.Join(kept, "\n")+"\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(t); code != http.StatusConflict {
			t.Fatalf("February's checkpoint gone: verify-chain %d %q, want 409", code, text)
		}
		if err := os.WriteFile(anchors, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(t); code != http.StatusOK {
			t.Fatalf("anchors restored: %d %s", code, text)
		}
	})
}

type reconciliationResponse struct {
	Outcomes []struct {
		InjectionID string `json:"injection_id"`
		SessionID   string `json:"session_id"`
		AccountID   string `json:"account_id"`
		Protocol    string `json:"protocol"`
		Emitter     string `json:"emitter"`
		Status      string `json:"status"`
		StartEvent  string `json:"start_event_id"`
		ResultEvent string `json:"result_event_id"`
	} `json:"outcomes"`
	Coverage                string `json:"coverage"`
	ArchivedHistoryExcluded bool   `json:"archived_history_excluded"`
	ArchivedEvents          int    `json:"archived_events"`
}

func assertArchivedInjections(t *testing.T, page reconciliationResponse) {
	t.Helper()
	if page.Coverage != "verified_archives_and_retained_chain" || page.ArchivedHistoryExcluded || page.ArchivedEvents != 5 || len(page.Outcomes) != 2 {
		t.Fatalf("archive reconciliation coverage: %+v", page)
	}
	want := map[string]struct{ session, account, protocol string }{
		"0123456789abcdef0123456789abcdef": {session: "sess_archived_jan", account: "acc_archived_jan", protocol: "ssh"},
		"fedcba9876543210fedcba9876543210": {session: "sess_archived_feb", account: "acc_archived_feb", protocol: "vnc"},
	}
	for _, outcome := range page.Outcomes {
		expected, ok := want[outcome.InjectionID]
		if !ok || outcome.Status != "completed" || outcome.SessionID != expected.session || outcome.AccountID != expected.account ||
			outcome.Protocol != expected.protocol || outcome.Emitter != "ssh-proxy" || outcome.StartEvent == "" || outcome.ResultEvent == "" {
			t.Fatalf("unexpected archived injection outcome: %+v", outcome)
		}
		delete(want, outcome.InjectionID)
	}
	if len(want) != 0 {
		t.Fatalf("missing archived injection outcomes: %+v", want)
	}
}

func insertAuditV4Event(t *testing.T, db *sql.DB, key, previousHash []byte, id string, timestamp time.Time,
	actorID, action, resourceType, resourceID, emitter string, details map[string]string, success bool) []byte {
	t.Helper()
	if details == nil {
		details = map[string]string{}
	}
	timestamp = timestamp.UTC().Truncate(time.Microsecond)
	keyID := auditChainKeyID(key)
	hash := auditV4Hash(key, previousHash, id, actorID, action, resourceType, resourceID, emitter, keyID, success, timestamp, details)
	rawDetails, err := json.Marshal(details)
	if err != nil {
		t.Fatal(err)
	}
	_, err = db.Exec(`INSERT INTO audit_events
		(id, ts, actor_id, action, resource_type, resource_id, details, success, prev_hash, hash, hash_version, emitter, chain_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 4, $11, $12)`,
		id, timestamp, actorID, action, resourceType, resourceID, string(rawDetails), success, previousHash, hash, emitter, keyID)
	if err != nil {
		t.Fatalf("insert historical audit event %s: %v", id, err)
	}
	return hash
}

func auditChainKeyID(key []byte) string {
	tagged := append([]byte("openbastion.audit.chain-key-id\x00"), key...)
	sum := sha256.Sum256(tagged)
	return hex.EncodeToString(sum[:8])
}

// auditV4Hash mirrors the persisted v4 framing only to seed historical rows. The real Audit
// Service independently verifies these HMACs when it archives and reconciles the records.
func auditV4Hash(key, previousHash []byte, id, actorID, action, resourceType, resourceID, emitter, keyID string,
	success bool, timestamp time.Time, details map[string]string) []byte {
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte("openbastion.audit.event.v4\x00"))
	var length [4]byte
	writeField := func(field []byte) {
		binary.BigEndian.PutUint32(length[:], uint32(len(field)))
		mac.Write(length[:])
		mac.Write(field)
	}
	for _, field := range [][]byte{previousHash, []byte(id), []byte(actorID), []byte(action), []byte(resourceType), []byte(resourceID), []byte(emitter), []byte(keyID)} {
		writeField(field)
	}
	var successByte [1]byte
	if success {
		successByte[0] = 1
	}
	mac.Write(successByte[:])
	var timestampBytes [8]byte
	binary.BigEndian.PutUint64(timestampBytes[:], uint64(timestamp.UnixNano()))
	mac.Write(timestampBytes[:])
	keys := make([]string, 0, len(details))
	for key := range details {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	binary.BigEndian.PutUint32(length[:], uint32(len(keys)))
	mac.Write(length[:])
	for _, key := range keys {
		writeField([]byte(key))
		writeField([]byte(details[key]))
	}
	return mac.Sum(nil)
}

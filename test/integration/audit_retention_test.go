package integration_test

// Archiving the audit chain out of the database without making it unverifiable (ADR-0032), on
// a real Audit Service against a real PostgreSQL.
//
// Before ADR-0032 nothing ever left audit_events: a retention could only be a deletion, and a
// deletion made the chain unverifiable. The claim: the months older than the retention are
// archived, checkpointed with the anchors and deleted, and the chain left still verifies —
// while a start cut without a checkpoint, or a checkpoint taken away, is still found.

import (
	"bufio"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_OldMonthsAreArchivedOutOfTheDatabase_AndTheChainStillVerifies(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	run := func(q string, args ...any) {
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

	// A chain written in January and February 2025, in the format with no key (what a
	// deployment upgraded from before ADR-0027 has), then the Audit Service of today.
	run(`TRUNCATE audit_events RESTART IDENTITY`)
	t.Cleanup(func() { _, _ = db.Exec(`TRUNCATE audit_events RESTART IDENTITY`) })
	var prev []byte
	for i, ts := range []time.Time{
		time.Date(2025, 1, 3, 9, 0, 0, 0, time.UTC), time.Date(2025, 1, 4, 9, 0, 0, 0, time.UTC), time.Date(2025, 1, 31, 23, 59, 59, 0, time.UTC),
		time.Date(2025, 2, 1, 0, 0, 0, 0, time.UTC), time.Date(2025, 2, 27, 9, 0, 0, 0, time.UTC),
	} {
		id := fmt.Sprintf("evt_2025_%d", i)
		hash := v2Hash(prev, id, "user_a", "session.connect", "session", "session_old", true, ts)
		run(`INSERT INTO audit_events (id, ts, actor_id, action, resource_type, resource_id, success, prev_hash, hash, hash_version)
			VALUES ($1, $2, 'user_a', 'session.connect', 'session', 'session_old', true, $3, $4, 2)`, id, ts, nullBytes(prev), hash)
		prev = hash
	}

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
	verify := func() (int, string) {
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
		if code, text := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain after archiving: %d %s", code, text)
		}
		if !strings.Contains(audit.out.String(), "archived audit-2025-01.jsonl") {
			t.Fatalf("the archiving is not in the log:\n%s", audit.out.String())
		}
	})

	t.Run("the start of the chain cut past the checkpoint is found", func(t *testing.T) {
		run(`DROP TABLE IF EXISTS audit_retention_snapshot`)
		run(`CREATE TABLE audit_retention_snapshot AS SELECT * FROM audit_events`)
		t.Cleanup(func() { _, _ = db.Exec(`DROP TABLE IF EXISTS audit_retention_snapshot`) })
		run(`DELETE FROM audit_events WHERE seq = (SELECT min(seq) FROM audit_events)`)
		if code, text := verify(); code != http.StatusConflict {
			t.Fatalf("the first event left deleted: verify-chain %d %q, want 409", code, text)
		}
		run(`DELETE FROM audit_events`)
		run(`INSERT INTO audit_events SELECT * FROM audit_retention_snapshot`)
		if code, text := verify(); code != http.StatusOK {
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
		if code, text := verify(); code != http.StatusConflict {
			t.Fatalf("February's checkpoint gone: verify-chain %d %q, want 409", code, text)
		}
		if err := os.WriteFile(anchors, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(); code != http.StatusOK {
			t.Fatalf("anchors restored: %d %s", code, text)
		}
	})
}

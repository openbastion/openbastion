package integration_test

// The head of the audit chain is anchored outside the database (ADR-0028), on a real Audit
// Service against a real PostgreSQL, with an anchor file the database does not control.
//
// ADR-0027 left two attacks open to somebody who can write audit_events: rewrite the WHOLE
// chain, from its first event, in a format that needs no key — nothing in the database says it
// was ever keyed —, and cut the end of the chain. This is both, written first and seen to fail.

import (
	"bufio"
	"context"
	"database/sql"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_TheChainIsAnchoredOutsideTheDatabase_ARewriteOrACutIsFound(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`TRUNCATE audit_events RESTART IDENTITY`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = db.Exec(`TRUNCATE audit_events RESTART IDENTITY`)
		_, _ = db.Exec(`DROP TABLE IF EXISTS audit_anchor_snapshot`)
	})

	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-28")
	key := testKMSKeyHex(t)
	anchors := t.TempDir() + "/anchors.jsonl"

	t.Run("with a database the anchors are required, and their pace is bounded", func(t *testing.T) {
		for _, env := range [][]string{
			{"AUDIT_CHAIN_KEY_HEX=" + key},
			{"AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=0"},
			{"AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=3601"},
			{"AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=off"},
			{"AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_ANCHOR_FILE=/nonexistent-dir/anchors.jsonl"},
		} {
			out := runUntilExit(t, root, auditBin, append([]string{"PORT=19453", "DATABASE_URL=" + dsn}, env...)...)
			if !strings.Contains(out, "AUDIT_ANCHOR_") {
				t.Fatalf("%v: expected a refusal to start naming the variable, got:\n%s", env, out)
			}
			if len(env) == 1 && !strings.Contains(out, "AUDIT_ANCHOR_FILE is required") {
				t.Fatalf("no anchor file: expected the refusal to say it is required, got:\n%s", out)
			}
		}
	})

	audit := startService(t, root, auditBin, "19451", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key,
		"AUDIT_ANCHOR_FILE="+anchors, "AUDIT_ANCHOR_INTERVAL_SECONDS=1")
	emitter := &httpAuditEmitter{baseURL: audit.baseURL}
	for _, res := range []string{"session_a", "session_b", "session_c", "session_d"} {
		if err := emitter.EmitEvent(context.Background(), "session.connect", "session", res, true); err != nil {
			t.Fatal(err)
		}
	}
	var lastID string
	_ = db.QueryRow(`SELECT id FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastID)
	waitUntil(t, 5*time.Second, "an anchor naming the head of the chain", func() bool {
		raw, _ := os.ReadFile(anchors)
		return strings.Contains(string(raw), lastID)
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
	if code, text := verify(); code != http.StatusOK {
		t.Fatalf("verify-chain on an anchored chain: %d %s", code, text)
	}
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_anchor_snapshot`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_anchor_snapshot AS SELECT * FROM audit_events`); err != nil {
		t.Fatal(err)
	}
	restore := func() {
		t.Helper()
		for _, q := range []string{`DELETE FROM audit_events`, `INSERT INTO audit_events SELECT * FROM audit_anchor_snapshot`} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		if code, text := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain once restored: %d %s", code, text)
		}
	}

	t.Run("the whole chain rewritten from its first event in a format with no key is found", func(t *testing.T) {
		events := load(t, db)
		var prev []byte
		for i, e := range events {
			res := e.res
			if i == 1 {
				res = "session_forged"
			}
			hash := v2Hash(prev, e.id, e.actor, e.action, e.typ, res, e.success, e.ts)
			if _, err := db.Exec(`UPDATE audit_events SET resource_id = $1, prev_hash = $2, hash = $3, hash_version = 2, emitter = '', chain_key_id = '' WHERE seq = $4`,
				res, nullBytes(prev), hash, e.seq); err != nil {
				t.Fatal(err)
			}
			prev = hash
		}
		if code, text := verify(); code != http.StatusConflict || !strings.Contains(text, "anchor") {
			t.Fatalf("a whole chain rewritten in v2: verify-chain %d %q, want 409 naming the anchor", code, text)
		}
		restore()
	})

	t.Run("the end of the chain cut up to an anchor is found", func(t *testing.T) {
		if _, err := db.Exec(`DELETE FROM audit_events WHERE seq >= 3`); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(); code != http.StatusConflict || !strings.Contains(text, "anchor") {
			t.Fatalf("the last events deleted: verify-chain %d %q, want 409 naming the anchor", code, text)
		}
		restore()
	})

	t.Run("an anchor edited in the file is found", func(t *testing.T) {
		raw, err := os.ReadFile(anchors)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
		forged := strings.Replace(lines[len(lines)-1], lastID, "evt_forged", 1)
		edited := strings.Join(append(lines[:len(lines)-1], forged), "\n") + "\n"
		if err := os.WriteFile(anchors, []byte(edited), 0o600); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(); code != http.StatusConflict || !strings.Contains(text, "anchor") {
			t.Fatalf("an edited anchor: verify-chain %d %q, want 409", code, text)
		}
		if err := os.WriteFile(anchors, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(); code != http.StatusOK {
			t.Fatalf("anchors restored: %d %s", code, text)
		}
	})

	t.Run("the anchors cannot be read: the chain cannot be vouched for (503, not 200)", func(t *testing.T) {
		raw, _ := os.ReadFile(anchors)
		if err := os.Remove(anchors); err != nil {
			t.Fatal(err)
		}
		if code, text := verify(); code != http.StatusServiceUnavailable {
			t.Fatalf("anchors file gone: verify-chain %d %q, want 503", code, text)
		}
		if err := os.WriteFile(anchors, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("each anchor names a head the chain has had, once", func(t *testing.T) {
		f, err := os.Open(anchors)
		if err != nil {
			t.Fatal(err)
		}
		defer f.Close()
		seen := map[string]bool{}
		sc := bufio.NewScanner(f)
		for sc.Scan() {
			if seen[sc.Text()] {
				t.Fatalf("the same anchor twice: %s", sc.Text())
			}
			seen[sc.Text()] = true
		}
		// The head has not moved for several intervals: no new anchor for the same head.
		before := len(seen)
		time.Sleep(2500 * time.Millisecond)
		raw, _ := os.ReadFile(anchors)
		if n := len(strings.Split(strings.TrimSpace(string(raw)), "\n")); n != before {
			t.Fatalf("%d anchors after waiting with no new event, want %d", n, before)
		}
	})
}

func load(t *testing.T, db *sql.DB) []storedEvent {
	t.Helper()
	rows, err := db.Query(`SELECT seq, id, COALESCE(actor_id, ''), action, resource_type, resource_id, success, ts, hash_version FROM audit_events ORDER BY seq`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []storedEvent
	for rows.Next() {
		var e storedEvent
		if err := rows.Scan(&e.seq, &e.id, &e.actor, &e.action, &e.typ, &e.res, &e.success, &e.ts, &e.version); err != nil {
			t.Fatal(err)
		}
		out = append(out, e)
	}
	return out
}

func nullBytes(b []byte) any {
	if b == nil {
		return nil
	}
	return b
}

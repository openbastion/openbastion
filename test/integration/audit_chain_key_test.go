package integration_test

// The audit chain is keyed (ADR-0027), on a real Audit Service against a real PostgreSQL.
//
// Before ADR-0027 the chain had no key: somebody who can write to audit_events — and who has
// read the formats, which are public — could rewrite an event and recompute every hash and link
// after it, and verify-chain said the trail was whole. This is that attack, written first and
// seen to fail: the attacker recomputes the tail in every format he can compute without the key.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// v2Hash is ADR-0026's format, written out from its description: what an attacker without
// the key can compute.
func v2Hash(prev []byte, id, actor, action, typ, res string, success bool, ts time.Time) []byte {
	h := sha256.New()
	h.Write([]byte("openbastion.audit.event.v2\x00"))
	var n [4]byte
	for _, f := range [][]byte{prev, []byte(id), []byte(actor), []byte(action), []byte(typ), []byte(res)} {
		binary.BigEndian.PutUint32(n[:], uint32(len(f)))
		h.Write(n[:])
		h.Write(f)
	}
	if success {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(ts.UnixNano()))
	h.Write(b[:])
	return h.Sum(nil)
}

type storedEvent struct {
	seq                         int64
	id, actor, action, typ, res string
	success                     bool
	ts                          time.Time
	version                     int
}

func TestPostgresFlow_TheAuditChainIsKeyed_ARewrittenTailIsFound_AndTheKeyIsRequired(t *testing.T) {
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
	t.Cleanup(func() { _, _ = db.Exec(`TRUNCATE audit_events RESTART IDENTITY`) })

	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-27")
	key, otherKey := testKMSKeyHex(t), testKMSKeyHex(t)
	anchors := t.TempDir() + "/anchors.jsonl"

	t.Run("with a database the chain needs a key: none, or one that is not a key, stops the service", func(t *testing.T) {
		for _, env := range [][]string{
			{"DATABASE_URL=" + dsn, "AUDIT_ANCHOR_FILE=" + anchors},
			{"DATABASE_URL=" + dsn, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_CHAIN_KEY_HEX=abcd"},
			{"DATABASE_URL=" + dsn, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_CHAIN_KEY_HEX=" + strings.Repeat("zz", 32)},
			{"DATABASE_URL=" + dsn, "AUDIT_ANCHOR_FILE=" + anchors, "AUDIT_CHAIN_KEY_HEX=" + key, "AUDIT_CHAIN_PREVIOUS_KEYS_HEX=nothex"},
		} {
			out := runUntilExit(t, root, auditBin, append([]string{"PORT=19446"}, env...)...)
			if !strings.Contains(out, "AUDIT_CHAIN_") {
				t.Fatalf("%v: expected a refusal to start naming the variable, got:\n%s", env, out)
			}
			if strings.Contains(out, key) {
				t.Fatalf("the key is in the output:\n%s", out)
			}
		}
	})

	audit := startService(t, root, auditBin, "19441", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key, "AUDIT_ANCHOR_FILE="+anchors)
	emitter := &httpAuditEmitter{baseURL: audit.baseURL}
	for _, res := range []string{"session_a", "session_b", "session_c"} {
		if err := emitter.EmitEvent(context.Background(), "session.connect", "session", res, true); err != nil {
			t.Fatal(err)
		}
	}
	verify := func(base string) int {
		t.Helper()
		resp, err := http.Get(base + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	if code := verify(audit.baseURL); code != http.StatusOK {
		t.Fatalf("verify-chain on an untouched keyed chain: %d", code)
	}
	load := func() []storedEvent {
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
	// A snapshot of what the service wrote, to put the chain back after each attack.
	if _, err := db.Exec(`DROP TABLE IF EXISTS audit_chain_snapshot`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE audit_chain_snapshot AS SELECT seq, resource_id, prev_hash, hash, hash_version FROM audit_events`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`DROP TABLE IF EXISTS audit_chain_snapshot`) })

	t.Run("an event rewritten in the database, with the whole tail recomputed without the key, is found", func(t *testing.T) {
		for _, asVersion := range []int{2, 3} {
			events := load()
			var prev []byte
			_ = db.QueryRow(`SELECT prev_hash FROM audit_events WHERE seq = $1`, events[1].seq).Scan(&prev)
			for i := 1; i < len(events); i++ {
				e := events[i]
				res := e.res
				if i == 1 {
					res = "session_forged"
				}
				hash := v2Hash(prev, e.id, e.actor, e.action, e.typ, res, e.success, e.ts)
				if _, err := db.Exec(`UPDATE audit_events SET resource_id = $1, prev_hash = $2, hash = $3, hash_version = $4 WHERE seq = $5`,
					res, prev, hash, asVersion, e.seq); err != nil {
					t.Fatal(err)
				}
				prev = hash
			}
			if code := verify(audit.baseURL); code != http.StatusConflict {
				t.Fatalf("a tail recomputed in the public format, labelled v%d: verify-chain %d, want 409", asVersion, code)
			}
			// Put the chain back as the service wrote it.
			restoreChain(t, db)
			if code := verify(audit.baseURL); code != http.StatusOK {
				t.Fatalf("verify-chain once restored: %d", code)
			}
		}
	})

	stopService(t, audit)

	t.Run("a restart with the same key continues the chain", func(t *testing.T) {
		again := startService(t, root, auditBin, "19442", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+key, "AUDIT_ANCHOR_FILE="+anchors)
		if err := (&httpAuditEmitter{baseURL: again.baseURL}).EmitEvent(context.Background(), "session.terminate", "session", "session_a", true); err != nil {
			t.Fatal(err)
		}
		if code := verify(again.baseURL); code != http.StatusOK {
			t.Fatalf("verify-chain after a restart with the same key: %d", code)
		}
		stopService(t, again)
	})

	t.Run("a new key cannot vouch for what the old one signed — unless the old one is kept for verification", func(t *testing.T) {
		rotated := startService(t, root, auditBin, "19443", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+otherKey, "AUDIT_ANCHOR_FILE="+anchors)
		resp, err := http.Get(rotated.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		raw := make([]byte, 512)
		n, _ := resp.Body.Read(raw)
		resp.Body.Close()
		if resp.StatusCode != http.StatusConflict || !strings.Contains(string(raw[:n]), "key") {
			t.Fatalf("verify-chain with another key: %d %q, want 409 saying the key is not held", resp.StatusCode, raw[:n])
		}
		stopService(t, rotated)

		withOld := startService(t, root, auditBin, "19444", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+otherKey,
			"AUDIT_CHAIN_PREVIOUS_KEYS_HEX="+key, "AUDIT_ANCHOR_FILE="+anchors)
		if err := (&httpAuditEmitter{baseURL: withOld.baseURL}).EmitEvent(context.Background(), "session.connect", "session", "session_d", true); err != nil {
			t.Fatal(err)
		}
		if code := verify(withOld.baseURL); code != http.StatusOK {
			t.Fatalf("verify-chain with the old key kept for verification: %d", code)
		}
	})
}

// restoreChain writes back the fields, links, hashes and versions the service wrote.
func restoreChain(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`UPDATE audit_events a SET resource_id = s.resource_id, prev_hash = s.prev_hash, hash = s.hash, hash_version = s.hash_version
		FROM audit_chain_snapshot s WHERE a.seq = s.seq`); err != nil {
		t.Fatal(err)
	}
}

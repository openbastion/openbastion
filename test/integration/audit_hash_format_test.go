package integration_test

// The hash of an audit event covers each field as a field (ADR-0026), on a real Audit Service
// against a real PostgreSQL holding a chain written before the change.
//
// Before ADR-0026 the hash concatenated the fields as they were: moving a byte from actor_id
// to action, in the database, left every hash and every link as it was, and verify-chain said
// the trail was whole. The claims: a chain written in the old format still verifies after the
// upgrade, grows in the new one, and in the new one a byte moved between two fields, or a
// version relabelled, is found.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"
)

// legacyHash is the format the Audit Service wrote before ADR-0026, written out here from its
// description so that this test does not borrow the code it checks.
func legacyHash(prev []byte, id, actor, action, typ, res string, success bool, ts time.Time) []byte {
	h := sha256.New()
	h.Write(prev)
	for _, f := range []string{id, actor, action, typ, res} {
		h.Write([]byte(f))
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

func TestPostgresFlow_ALegacyChainIsUpgradedInPlace_AndTheNewFormatFindsBytesMovedBetweenFields(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	// A database as a deployment from before ADR-0026 has it: no hash_version, a v1 chain.
	exec(`CREATE TABLE IF NOT EXISTS audit_events (seq BIGSERIAL PRIMARY KEY, id TEXT NOT NULL UNIQUE, ts TIMESTAMPTZ NOT NULL,
		actor_id TEXT, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, success BOOLEAN NOT NULL,
		prev_hash BYTEA, hash BYTEA NOT NULL)`)
	exec(`TRUNCATE audit_events RESTART IDENTITY`)
	exec(`ALTER TABLE audit_events DROP COLUMN IF EXISTS hash_version`)
	var prev []byte
	t0 := time.Date(2026, 9, 1, 8, 0, 0, 0, time.UTC)
	for i, actor := range []string{"user_ab", "user_cd", "user_ef"} {
		id, ts := fmt.Sprintf("evt_legacy_%d", i), t0.Add(time.Duration(i)*time.Second)
		hash := legacyHash(prev, id, actor, "session.connect", "session", "session_old", true, ts)
		exec(`INSERT INTO audit_events (id, ts, actor_id, action, resource_type, resource_id, success, prev_hash, hash)
			VALUES ($1, $2, $3, 'session.connect', 'session', 'session_old', true, $4, $5)`, id, ts, actor, prev, hash)
		prev = hash
	}

	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-26")
	audit := startService(t, root, auditBin, "19431", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+testKMSKeyHex(t))
	verify := func() int {
		t.Helper()
		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		return resp.StatusCode
	}
	versions := func() []int {
		t.Helper()
		rows, err := db.Query(`SELECT hash_version FROM audit_events ORDER BY seq`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out []int
		for rows.Next() {
			var v int
			_ = rows.Scan(&v)
			out = append(out, v)
		}
		return out
	}

	t.Run("the legacy chain verifies after the upgrade, and its rows are version 1", func(t *testing.T) {
		if code := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain on the upgraded database: %d", code)
		}
		if v := versions(); fmt.Sprint(v) != "[1 1 1]" {
			t.Fatalf("versions %v, want [1 1 1]", v)
		}
	})

	// Since ADR-0027 the format written is v3 (keyed), which frames fields as v2 does.
	t.Run("the chain grows in the current format and still verifies", func(t *testing.T) {
		emitter := &httpAuditEmitter{baseURL: audit.baseURL}
		for i := 0; i < 2; i++ {
			if err := emitter.EmitEvent(context.Background(), "session.read", "session", "session_new", true); err != nil {
				t.Fatal(err)
			}
		}
		if v := versions(); fmt.Sprint(v) != "[1 1 1 3 3]" {
			t.Fatalf("versions %v, want [1 1 1 3 3]", v)
		}
		if code := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain, v1 then v3: %d", code)
		}
	})

	t.Run("in the current format, a byte moved between two fields in the database is found", func(t *testing.T) {
		exec(`UPDATE audit_events SET action = 'session.rea', resource_type = 'dsession' WHERE seq = 4`)
		if code := verify(); code != http.StatusConflict {
			t.Fatalf("verify-chain after moving a byte from action to resource_type: %d, want 409", code)
		}
		exec(`UPDATE audit_events SET action = 'session.read', resource_type = 'session' WHERE seq = 4`)
		if code := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain once restored: %d", code)
		}
	})

	t.Run("a version relabelled in the database is found", func(t *testing.T) {
		exec(`UPDATE audit_events SET hash_version = 1 WHERE seq = 5`)
		if code := verify(); code != http.StatusConflict {
			t.Fatalf("verify-chain after relabelling a v3 row as v1: %d, want 409", code)
		}
		exec(`UPDATE audit_events SET hash_version = 3 WHERE seq = 5`)
		if code := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain once restored: %d", code)
		}
	})

	t.Run("the limit that stays: in a legacy row, the same move is not found", func(t *testing.T) {
		// ADR-0026 does not re-hash history (that would destroy the evidence it protects): the
		// rows written before it keep the weakness they were written with. Asserted so that the
		// documents that say so stay true.
		exec(`UPDATE audit_events SET actor_id = 'user_a', action = 'bsession.connect' WHERE seq = 1`)
		if code := verify(); code != http.StatusOK {
			t.Fatalf("verify-chain: %d — if a v1 row is now protected, update ADR-0026 and the Guide Sécurité", code)
		}
	})

	// Leave nothing for the tests that run after this one: a chain they did not write.
	exec(`TRUNCATE audit_events RESTART IDENTITY`)
}

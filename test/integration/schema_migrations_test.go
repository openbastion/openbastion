package integration_test

// Schema migrations are versioned, applied once, under a lock (ADR-0030), on real processes
// against a real PostgreSQL.
//
// Before ADR-0030 every service ran the whole of its 001_init.sql at every start. Two replicas
// started together on a fresh database ran it at the same time, and IF NOT EXISTS does not
// stop two concurrent creations: one of them failed, and the replica did not start. This is
// that, written first and seen to fail.

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_ReplicasStartingTogetherOnAFreshDatabase_AllStart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	root := repoRoot(t)
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-30")
	unreachable := "http://127.0.0.1:1"
	const rounds, replicas = 5, 4

	failed := 0
	for round := 0; round < rounds; round++ {
		// A fresh database, as far as the Session Broker is concerned.
		for _, q := range []string{
			`DROP TABLE IF EXISTS sessions CASCADE`,
			`DO $$ BEGIN IF to_regclass('schema_migrations') IS NOT NULL THEN
				DELETE FROM schema_migrations WHERE component = 'session-broker'; END IF; END $$`,
		} {
			if _, err := db.Exec(q); err != nil {
				t.Fatal(err)
			}
		}
		cmds := make([]*exec.Cmd, replicas)
		outs := make([]*syncBuffer, replicas)
		for i := range cmds {
			cmds[i] = exec.Command(brokerBin)
			cmds[i].Env = append(buildEnv(root), fmt.Sprintf("PORT=%d", 19461+i), "DATABASE_URL="+dsn,
				"AUTHORIZATION_URL="+unreachable, "AUDIT_URL="+unreachable, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable)
			outs[i] = &syncBuffer{}
			cmds[i].Stdout, cmds[i].Stderr = outs[i], outs[i]
		}
		for _, c := range cmds {
			if err := c.Start(); err != nil {
				t.Fatal(err)
			}
		}
		for i, c := range cmds {
			if !becomesHealthy(fmt.Sprintf("http://127.0.0.1:%d", 19461+i), 10*time.Second) {
				failed++
				t.Logf("round %d, replica %d did not start:\n%s", round, i, outs[i].String())
			}
			_ = c.Process.Kill()
			_ = c.Wait()
		}
	}
	if failed != 0 {
		t.Fatalf("%d of %d replicas started together on a fresh database did not start", failed, rounds*replicas)
	}

	t.Run("the schema the replicas agreed on is recorded once, as version 1", func(t *testing.T) {
		var n int
		if err := db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE component = 'session-broker' AND version = 1`).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%d rows for session-broker version 1, want 1", n)
		}
	})

	brokerEnv := []string{"PORT=19465", "DATABASE_URL=" + dsn,
		"AUTHORIZATION_URL=" + unreachable, "AUDIT_URL=" + unreachable, "VAULT_URL=" + unreachable, "SSH_PROXY_URL=" + unreachable}
	run := func(q string) {
		t.Helper()
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	t.Run("a database from before versioned migrations keeps its data and is recorded as version 1", func(t *testing.T) {
		t.Cleanup(func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = 'session_before_adr30'`) })
		run(`INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at)
			VALUES ('session_before_adr30', 'active', 'ssh', 'user_a', 'acc_1', 'written before ADR-0030', now(), now() + interval '1 hour')`)
		run(`DELETE FROM schema_migrations WHERE component = 'session-broker'`)
		broker := startService(t, root, brokerBin, "19465", brokerEnv[1:]...)
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM sessions WHERE id = 'session_before_adr30'`).Scan(&n)
		if n != 1 {
			t.Fatal("the session written before the upgrade is gone")
		}
		_ = db.QueryRow(`SELECT count(*) FROM schema_migrations WHERE component = 'session-broker' AND version = 1`).Scan(&n)
		if n != 1 {
			t.Fatalf("%d rows for version 1 after the upgrade, want 1", n)
		}
		if !strings.Contains(broker.out.String(), "schema migrations [1] applied") {
			t.Fatalf("the upgrade is not said:\n%s", broker.out.String())
		}
		stopService(t, broker)
	})

	t.Run("a migration changed after it was applied stops the service, naming it", func(t *testing.T) {
		run(`UPDATE schema_migrations SET checksum = '\x00' WHERE component = 'session-broker' AND version = 1`)
		out := runUntilExit(t, root, brokerBin, brokerEnv...)
		if !strings.Contains(out, "001_init.sql") || !strings.Contains(out, "changed after it was applied") {
			t.Fatalf("expected a refusal naming the migration, got:\n%s", out)
		}
		run(`DELETE FROM schema_migrations WHERE component = 'session-broker'`)
	})

	t.Run("a database newer than the binary: the service starts, and says so", func(t *testing.T) {
		broker := startService(t, root, brokerBin, "19465", brokerEnv[1:]...)
		stopService(t, broker)
		run(`INSERT INTO schema_migrations (component, version, name, checksum) VALUES ('session-broker', 99, '099_future.sql', '\x00')`)
		broker = startService(t, root, brokerBin, "19465", brokerEnv[1:]...)
		if !strings.Contains(broker.out.String(), "WARNING the database has schema migrations [99]") {
			t.Fatalf("a newer database is not said:\n%s", broker.out.String())
		}
		stopService(t, broker)
		run(`DELETE FROM schema_migrations WHERE component = 'session-broker' AND version = 99`)
	})
}

// becomesHealthy says whether the service answers /healthz with 200 within the limit.
func becomesHealthy(baseURL string, limit time.Duration) bool {
	for deadline := time.Now().Add(limit); time.Now().Before(deadline); time.Sleep(50 * time.Millisecond) {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return true
		}
	}
	return false
}

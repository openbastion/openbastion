package integration_test

// A session or a request past its end is marked expired, once, and the expiry is in the trail
// (ADR-0034), on a real Session Broker against a real PostgreSQL.
//
// Before ADR-0034 expiry was only read: a session granted and never connected, or a
// break-glass request no one decided, ended without a trace, and the database said "active"
// or "pending_approval" for ever. This is that, written first and seen to fail.

import (
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_SessionsPastTheirEndAreExpiredOnce_AndTheExpiryIsAudited(t *testing.T) {
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
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-34")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-34")
	unreachable := "http://127.0.0.1:1"

	t.Run("the sweep's pace is bounded", func(t *testing.T) {
		for _, v := range []string{"0", "3601", "often"} {
			out := runUntilExit(t, root, brokerBin, "PORT=19483", "AUTHORIZATION_URL="+unreachable, "AUDIT_URL="+unreachable,
				"VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS="+v)
			if !strings.Contains(out, "SESSION_EXPIRY_SWEEP_SECONDS") {
				t.Fatalf("%q: expected a refusal naming the variable, got:\n%s", v, out)
			}
		}
	})

	if _, err := db.Exec(`TRUNCATE sessions`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = db.Exec(`TRUNCATE sessions`) })
	insert := func(id, status string, end time.Time, breakGlass bool) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, break_glass)
			VALUES ($1, $2, 'ssh', 'user_a', 'acc_1', 'expiry test', $3, $4, $5)`, id, status, end.Add(-time.Hour), end, breakGlass); err != nil {
			t.Fatal(err)
		}
	}
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	insert("session_granted_never_used", "active", past, false)
	insert("session_request_never_decided", "pending_approval", past, true)
	insert("session_still_running", "active", future, false)
	insert("session_terminated_before", "terminated", past, false)
	insert("session_denied_before", "denied", past, false)

	audit := startService(t, root, auditBin, "19481")
	spy := startAuditSpy(t, audit.baseURL)
	spy.setDown(true) // the first sweeps cannot write: the expiries must wait, not be lost
	broker := startService(t, root, brokerBin, "19482", "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
		"AUDIT_URL="+spy.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")
	status := func(id string) string {
		var s string
		_ = db.QueryRow(`SELECT status FROM sessions WHERE id = $1`, id).Scan(&s)
		return s
	}

	t.Run("past their end, an unused session and an undecided request are marked expired in the database", func(t *testing.T) {
		waitUntil(t, 10*time.Second, "both expired", func() bool {
			return status("session_granted_never_used") == "expired" && status("session_request_never_decided") == "expired"
		})
	})

	t.Run("the audit down, the expiries wait — then each is written, by the Broker, as a system action", func(t *testing.T) {
		time.Sleep(2500 * time.Millisecond)
		var waiting int
		_ = db.QueryRow(`SELECT count(*) FROM sessions WHERE status = 'expired' AND NOT expiry_audited`).Scan(&waiting)
		if waiting != 2 {
			t.Fatalf("%d expiries waiting for the audit, want 2", waiting)
		}
		spy.setDown(false)
		spy.waitFor(t, "session.expire", "session_granted_never_used", true)
		spy.waitFor(t, "session.expire", "session_request_never_decided", true)
		waitUntil(t, 10*time.Second, "both marked as audited", func() bool {
			var n int
			_ = db.QueryRow(`SELECT count(*) FROM sessions WHERE status = 'expired' AND NOT expiry_audited`).Scan(&n)
			return n == 0
		})
	})

	t.Run("each expiry once; nothing else touched", func(t *testing.T) {
		time.Sleep(2500 * time.Millisecond) // several more sweeps
		spy.mu.Lock()
		counts := map[string]int{}
		for _, e := range spy.events {
			if e.Action == "session.expire" {
				counts[e.ResourceID]++
				if e.ActorID != "" || e.ResourceType != "session" || !e.Success {
					t.Errorf("an expiry event not written as a system action on a session: %+v", e)
				}
			}
		}
		spy.mu.Unlock()
		if len(counts) != 2 || counts["session_granted_never_used"] != 1 || counts["session_request_never_decided"] != 1 {
			t.Fatalf("expiry events %v, want one for each of the two sessions past their end", counts)
		}
		for id, want := range map[string]string{"session_still_running": "active", "session_terminated_before": "terminated", "session_denied_before": "denied"} {
			if got := status(id); got != want {
				t.Fatalf("%s is %q, want %q untouched", id, got, want)
			}
		}
	})
	stopService(t, broker)

	t.Run("two Brokers sweeping together expire each session once", func(t *testing.T) {
		for i := 0; i < 40; i++ {
			insert("session_race_"+string(rune('a'+i%26))+string(rune('a'+i/26)), "active", past, false)
		}
		spy.mu.Lock()
		spy.events = nil
		spy.mu.Unlock()
		for _, port := range []string{"19484", "19485"} {
			startService(t, root, brokerBin, port, "DATABASE_URL="+dsn, "AUTHORIZATION_URL="+unreachable,
				"AUDIT_URL="+spy.baseURL, "VAULT_URL="+unreachable, "SSH_PROXY_URL="+unreachable, "SESSION_EXPIRY_SWEEP_SECONDS=1")
		}
		waitUntil(t, 15*time.Second, "the forty expired and audited", func() bool {
			var n int
			_ = db.QueryRow(`SELECT count(*) FROM sessions WHERE id LIKE 'session_race_%' AND status = 'expired' AND expiry_audited`).Scan(&n)
			return n == 40
		})
		spy.mu.Lock()
		defer spy.mu.Unlock()
		counts := map[string]int{}
		for _, e := range spy.events {
			if e.Action == "session.expire" {
				counts[e.ResourceID]++
			}
		}
		for id, n := range counts {
			if n != 1 {
				t.Fatalf("%s expired %d times", id, n)
			}
		}
		if len(counts) != 40 {
			t.Fatalf("%d expiry events, want 40", len(counts))
		}
	})
}

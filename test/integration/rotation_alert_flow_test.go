package integration_test

// ADR-0041 across real processes and a real database: a Vault outside its rotation window
// takes no account, however overdue; a Vault within it rotates the account that is due, and a
// scheduled account whose target cannot be reached is counted as failing and raises
// vault.rotation_overdue. A window that does not read stops the Vault from starting.

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

// windowAround is a window of an hour, in UTC, starting offset hours from now.
func windowAround(offset int) string {
	start := time.Now().UTC().Add(time.Duration(offset) * time.Hour)
	end := start.Add(time.Hour)
	return fmt.Sprintf("%02d:%02d-%02d:%02d", start.Hour(), start.Minute(), end.Hour(), end.Minute())
}

func vaultAccount(t *testing.T, vaultURL, id string) map[string]any {
	t.Helper()
	resp, err := http.Get(vaultURL + "/vault/v1/accounts/" + id)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&got)
	return got
}

func TestPostgresFlow_ScheduledRotations_KeepToTheirWindow_AndFailuresRaiseAnAlert(t *testing.T) {
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
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-41")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-41")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-41")

	t.Run("a window that does not read stops the Vault", func(t *testing.T) {
		for _, bad := range []string{"2-5", "02:00-02:00", "25:00-01:00"} {
			out := runUntilExit(t, root, vaultBin, "PORT=18479", "SKIP_DEMO_SEED=1", "ROTATION_WINDOW_UTC="+bad)
			if !strings.Contains(out, "ROTATION_WINDOW_UTC") {
				t.Fatalf("%q: the refusal does not name the variable:\n%s", bad, out)
			}
		}
		out := runUntilExit(t, root, vaultBin, "PORT=18479", "SKIP_DEMO_SEED=1", "ROTATION_ALERT_AFTER_FAILURES=0")
		if !strings.Contains(out, "ROTATION_ALERT_AFTER_FAILURES") {
			t.Fatalf("a threshold of 0 was not refused by name:\n%s", out)
		}
	})

	authz := startService(t, root, authzBin, "18471")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	audit := startService(t, root, auditBin, "18472")
	spy := startAuditSpy(t, audit.baseURL)
	kms := testKMSKeyHex(t)
	env := func(extra ...string) []string {
		return append([]string{"AUTHORIZATION_URL=" + authz.baseURL, "DATABASE_URL=" + dsn, "KMS_KEY_HEX=" + kms, "SKIP_DEMO_SEED=1",
			"AUDIT_URL=" + spy.baseURL, "ROTATION_SWEEP_SECONDS=1"}, extra...)
	}

	// A target that answers, and an address where nothing listens.
	tgt := startRotatableTarget(t, map[string]string{"root": "w-root-pw", "app": "w-old-pw"})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	dead := ln.Addr().String()
	ln.Close()

	run := fmt.Sprintf("%d", time.Now().UnixNano())
	acc, gone := "acc_win_"+run, "acc_gone_"+run
	// Outside its window: two hours from now, for an hour.
	outside := startService(t, root, vaultBin, "18473", env("ROTATION_WINDOW_UTC="+windowAround(2), "ROTATION_ALERT_AFTER_FAILURES=1")...)
	onboard := func(body map[string]any) {
		t.Helper()
		body["protocol"], body["actorRoles"] = "ssh", []string{"vault-admin"}
		if s := vaultOnboard(t, outside.baseURL, body); s != http.StatusCreated {
			t.Fatalf("onboard %v: %d", body["id"], s)
		}
	}
	onboard(map[string]any{"id": acc + "_rec", "name": acc + "_rec", "username": "root", "targetHost": tgt.addr, "rotationPolicy": "manual", "initialSecret": []byte("w-root-pw")})
	onboard(map[string]any{"id": acc, "name": acc, "username": "app", "targetHost": tgt.addr, "rotationPolicy": "scheduled", "rotationIntervalDays": 1,
		"initialSecret": []byte("w-old-pw"), "reconciliationAccountId": acc + "_rec"})
	onboard(map[string]any{"id": gone + "_rec", "name": gone + "_rec", "username": "root", "targetHost": dead, "rotationPolicy": "manual", "initialSecret": []byte("x")})
	onboard(map[string]any{"id": gone, "name": gone, "username": "app", "targetHost": dead, "rotationPolicy": "scheduled", "rotationIntervalDays": 1,
		"initialSecret": []byte("y"), "reconciliationAccountId": gone + "_rec"})
	if _, err := db.ExecContext(context.Background(),
		`UPDATE privileged_accounts SET created_at = now() - interval '2 days' WHERE id = ANY($1)`, "{"+acc+","+gone+"}"); err != nil {
		t.Fatal(err)
	}

	t.Run("outside the window, nothing is taken, however overdue", func(t *testing.T) {
		time.Sleep(3 * time.Second)
		var taken int
		if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM privileged_accounts WHERE id = ANY($1) AND rotation_attempted_at IS NOT NULL`,
			"{"+acc+","+gone+"}").Scan(&taken); err != nil {
			t.Fatal(err)
		}
		if taken != 0 || tgt.password("app") != "w-old-pw" {
			t.Fatalf("%d account(s) taken, app=%q", taken, tgt.password("app"))
		}
	})
	_ = outside.cmd.Process.Kill()
	_ = outside.cmd.Wait()

	// The same base, a Vault whose window is now.
	inside := startService(t, root, vaultBin, "18474", env("ROTATION_WINDOW_UTC="+windowAround(0), "ROTATION_ALERT_AFTER_FAILURES=1")...)

	t.Run("within the window, the due account rotates", func(t *testing.T) {
		waitUntil(t, 20*time.Second, "the account to rotate", func() bool { return tgt.password("app") != "w-old-pw" })
		spy.waitFor(t, "vault.rotate", acc, true)
		if f := vaultAccount(t, inside.baseURL, acc)["rotationFailures"]; f != nil {
			t.Fatalf("a rotated account says %v failures", f)
		}
	})

	t.Run("an account whose target cannot be reached is counted, and alerts", func(t *testing.T) {
		spy.waitFor(t, "vault.rotation_overdue", gone, false)
		if f := vaultAccount(t, inside.baseURL, gone)["rotationFailures"]; f != float64(1) {
			t.Fatalf("rotationFailures = %v, want 1", f)
		}
		spy.mu.Lock()
		defer spy.mu.Unlock()
		for _, e := range spy.events {
			if e.ResourceID == gone && e.Action == "vault.rotation_overdue" && e.ActorID != "" {
				t.Fatalf("the alert names %q: it is the system's", e.ActorID)
			}
			if e.ResourceID == acc && e.Action == "vault.rotation_overdue" {
				t.Fatal("an account that rotated raised an alert")
			}
		}
	})
}

package integration_test

// Scheduled rotations (ADR-0040) across real processes and a real database: two Vaults sweep
// the same base every second; a scheduled account that is due rotates — once — on the
// target, as a system action, and the Vault then injects what the target takes. A manual
// account beside it, just as old, is left alone.

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

func TestPostgresFlow_AScheduledAccountRotatesOnItsOwn_OnceAcrossTwoVaults(t *testing.T) {
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
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-40")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-40")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-40")
	authz := startService(t, root, authzBin, "18461")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	audit := startService(t, root, auditBin, "18462")
	spy := startAuditSpy(t, audit.baseURL)
	kms := testKMSKeyHex(t)
	vaultEnv := []string{"AUTHORIZATION_URL=" + authz.baseURL, "DATABASE_URL=" + dsn, "KMS_KEY_HEX=" + kms, "SKIP_DEMO_SEED=1",
		"AUDIT_URL=" + spy.baseURL, "ROTATION_SWEEP_SECONDS=1"}
	vault1 := startService(t, root, vaultBin, "18463", vaultEnv...)
	startService(t, root, vaultBin, "18464", vaultEnv...)

	run := fmt.Sprintf("%d", time.Now().UnixNano())
	rec, acc, man := "acc_sched_rec_"+run, "acc_sched_"+run, "acc_sched_man_"+run
	tgt := startRotatableTarget(t, map[string]string{"root": "sched-root-pw", "app": "sched-old-pw", "ops": "sched-ops-pw"})
	onboard := func(body map[string]any) {
		t.Helper()
		body["targetHost"], body["protocol"], body["actorRoles"] = tgt.addr, "ssh", []string{"vault-admin"}
		if s := vaultOnboard(t, vault1.baseURL, body); s != http.StatusCreated {
			t.Fatalf("onboard %v: %d", body["id"], s)
		}
	}
	onboard(map[string]any{"id": rec, "name": rec, "username": "root", "rotationPolicy": "manual", "initialSecret": []byte("sched-root-pw")})
	onboard(map[string]any{"id": acc, "name": acc, "username": "app", "rotationPolicy": "scheduled", "rotationIntervalDays": 1,
		"initialSecret": []byte("sched-old-pw"), "reconciliationAccountId": rec})
	onboard(map[string]any{"id": man, "name": man, "username": "ops", "rotationPolicy": "manual",
		"initialSecret": []byte("sched-ops-pw"), "reconciliationAccountId": rec})

	// Freshly onboarded, nothing is due: three sweeps later, the target still has its password.
	time.Sleep(3 * time.Second)
	if tgt.password("app") != "sched-old-pw" {
		t.Fatal("an account that is not due was rotated")
	}

	// Two days pass — for both accounts.
	if _, err := db.ExecContext(context.Background(),
		`UPDATE privileged_accounts SET created_at = now() - interval '2 days' WHERE id = ANY($1)`, "{"+acc+","+man+"}"); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 20*time.Second, "the scheduled account to rotate on the target", func() bool { return tgt.password("app") != "sched-old-pw" })
	spy.waitFor(t, "vault.rotate", acc, true)
	if canLogIn(tgt.addr, "app", "sched-old-pw") {
		t.Fatal("the old password still opens the target")
	}

	// What the Vault injects is what the target takes.
	cred, err := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault1.baseURL}, "ssh-proxy-40").
		Fetch(context.Background(), authorizeScope(t, vault1.baseURL, "sched-session", acc, "ssh-proxy-40"))
	if err != nil {
		t.Fatal(err)
	}
	if string(cred.Material()) != tgt.password("app") {
		t.Fatal("the Vault injects a secret the target does not take")
	}
	cred.Purge()

	// Once, across the two Vaults, as the system; the manual account untouched.
	time.Sleep(3 * time.Second)
	requested, rotated := 0, 0
	spy.mu.Lock()
	for _, e := range spy.events {
		if e.ResourceID != acc && e.ResourceID != man {
			continue
		}
		if e.ResourceID == man {
			t.Errorf("the manual account was rotated: %+v", e)
		}
		if e.ActorID != "" {
			t.Errorf("a scheduled rotation names %q: it is a system action", e.ActorID)
		}
		switch {
		case e.Action == "vault.rotate_requested":
			requested++
		case e.Action == "vault.rotate" && e.Success:
			rotated++
		case strings.HasPrefix(e.Action, "vault.rotate"):
			t.Errorf("unexpected %+v", e)
		}
	}
	spy.mu.Unlock()
	if requested != 1 || rotated != 1 {
		t.Fatalf("%d rotation(s) requested and %d done across two Vaults, want 1 and 1", requested, rotated)
	}
	if tgt.password("ops") != "sched-ops-pw" {
		t.Fatal("the manual account's password changed")
	}
}

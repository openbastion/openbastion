// This file proves Password Vault's PostgreSQL-backed storage is real
// persistence: an account onboarded against one running password-vault
// process survives that process being killed and a brand new one
// started in its place, both pointed at the same database.
//
// Skipped, not failed, when TEST_DATABASE_URL is unset — see
// /NOTES_SANDBOX.md.
package integration_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// testKMSKeyHex generates a fresh random AES-256 key, hex-encoded, for
// KMS_KEY_HEX. Password Vault now refuses to start with DATABASE_URL set
// but no KMS_KEY_HEX (cmd/password-vault/main.go) — see
// infrastructure.NewLocalKMSFromHexKey's doc comment for why: without a
// stable key supplied from outside the process, a restarted process can
// never decrypt what a previous one sealed, which is exactly the bug this
// test exists to catch.
func testKMSKeyHex(t *testing.T) string {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generating test KMS key: %v", err)
	}
	return hex.EncodeToString(key[:])
}

// authzCheckAccess calls POST /authz/v1/check-access directly and returns
// whether access was allowed — a small, local helper since this file is
// the only one exercising Authorization's PostgreSQL-backed persistence
// directly (the other integration tests all go through CheckSession's own
// pass/fail assertions instead of inspecting the raw decision).
func authzCheckAccess(t *testing.T, baseURL string, actorRoles []string, resource, action string) bool {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"actor_roles": actorRoles, "resource": resource, "action": action,
	})
	resp, err := http.Post(baseURL+"/authz/v1/check-access", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("check-access: %v", err)
	}
	defer resp.Body.Close()
	var decision struct {
		Allowed bool `json:"allowed"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&decision)
	return decision.Allowed
}

func TestPostgresFlow_AccountSurvivesPasswordVaultProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-pg")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-pg")

	authz := startService(t, root, authzBin, "18401")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")

	// Unique per run: the database persists across runs by design, so a
	// fixed id would collide with itself on the second execution.
	accountID := fmt.Sprintf("acc_pg_restart_%d", time.Now().UnixNano())
	const secretValue = "postgres-restart-it-secret"
	kmsKeyHex := testKMSKeyHex(t) // shared across both processes below — see its doc comment

	vault1 := startService(t, root, vaultBin, "18402", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kmsKeyHex, "SKIP_DEMO_SEED=1")
	onboardAccountFull(t, vault1.baseURL, accountID, accountID, "root", accountID+":22", secretValue, []string{"vault-admin"})

	scopeToken := authorizeScope(t, vault1.baseURL, "pg-restart-session-1", accountID, "ssh-proxy-pg")
	fetcher1 := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault1.baseURL}, "ssh-proxy-pg")
	cred1, err := fetcher1.Fetch(context.Background(), scopeToken)
	if err != nil {
		t.Fatalf("Fetch from first process: %v", err)
	}
	if string(cred1.Material()) != secretValue {
		t.Fatalf("first process: got %q, want %q", cred1.Material(), secretValue)
	}
	cred1.Purge()

	// The process that did the onboarding is gone — the account must
	// live in the database, not in that process's memory.
	stopService(t, vault1)

	vault2 := startService(t, root, vaultBin, "18403", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kmsKeyHex, "SKIP_DEMO_SEED=1")

	scopeToken2 := authorizeScope(t, vault2.baseURL, "pg-restart-session-2", accountID, "ssh-proxy-pg")
	fetcher2 := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault2.baseURL}, "ssh-proxy-pg")
	cred2, err := fetcher2.Fetch(context.Background(), scopeToken2)
	if err != nil {
		t.Fatalf("Fetch from second, restarted process: %v", err)
	}
	if string(cred2.Material()) != secretValue {
		t.Fatalf("second process: got %q, want %q — the account did not survive the restart", cred2.Material(), secretValue)
	}
	cred2.Purge()

	t.Run("rotation on the restarted process persists too", func(t *testing.T) {
		body := map[string]any{"accountId": accountID, "actorRoles": []string{"vault-admin"}}
		if status := postJSON(t, vault2.baseURL+"/vault/v1/rotate", body); status != http.StatusAccepted {
			t.Fatalf("rotate: status %d", status)
		}

		scopeToken3 := authorizeScope(t, vault2.baseURL, "pg-restart-session-3", accountID, "ssh-proxy-pg")
		fetcher3 := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault2.baseURL}, "ssh-proxy-pg")
		cred3, err := fetcher3.Fetch(context.Background(), scopeToken3)
		if err != nil {
			t.Fatalf("Fetch after rotation: %v", err)
		}
		rotated := string(cred3.Material())
		cred3.Purge()
		if rotated == secretValue || rotated == "" {
			t.Fatalf("expected rotation to produce a new non-empty secret, got %q", rotated)
		}
	})
}

// TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart is
// Authorization's half of this increment: a policy created against one
// running authorization process must still be enforced by a second,
// independent process restarted against the same database — and that
// restart must never re-run the admin bootstrap (BootstrapAdminPolicy is
// a no-op once the store holds any row at all, in-memory or in Postgres
// alike; here specifically proven across a real process restart, not
// just within one process's lifetime like the application-layer tests).
func TestPostgresFlow_PolicySurvivesAuthorizationProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-pg-restart")

	// Unique per run — same rationale as accountID above: the policies
	// table's UNIQUE (role, resource_pattern, effect) constraint would
	// otherwise collide with a previous run's rows in this persistent
	// database.
	run := time.Now().UnixNano()
	role := fmt.Sprintf("role_pg_restart_%d", run)
	resourcePrefix := fmt.Sprintf("vault:account:pg-restart-%d-", run)
	resourcePattern := resourcePrefix + "*"
	resource := resourcePrefix + "01"

	authz1 := startService(t, root, authzBin, "18411", "DATABASE_URL="+dsn)
	authzCreatePolicy(t, authz1.baseURL, []string{"platform-admin"}, role, resourcePattern, "allow")

	if !authzCheckAccess(t, authz1.baseURL, []string{role}, resource, "session:create") {
		t.Fatal("sanity check failed: expected access to be granted before the restart")
	}

	// The process that created the policy is gone — the policy must live
	// in the database, not in that process's memory.
	stopService(t, authz1)

	authz2 := startService(t, root, authzBin, "18412", "DATABASE_URL="+dsn)

	if !authzCheckAccess(t, authz2.baseURL, []string{role}, resource, "session:create") {
		t.Fatal("expected the policy to survive the restart via PostgreSQL — a second, independent process did not see it")
	}

	t.Run("bootstrap does not re-grant admin access on a restart against an already-initialized database", func(t *testing.T) {
		if authzCheckAccess(t, authz2.baseURL, []string{"whoever-happens-to-restart-the-process"}, "authz:policy-admin", "authz:policy:create") {
			t.Fatal("restarting Authorization against a non-empty database must never re-run the admin bootstrap and hand out a fresh admin role")
		}
	})
}

// TestPasswordVaultMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex proves
// cmd/password-vault/main.go's fail-closed check directly, by running the
// real built binary (not a mock) and asserting it exits quickly rather
// than starting to listen. Unlike every other test in this file, it runs
// unconditionally — not gated on TEST_DATABASE_URL — because the check it
// exercises happens before main.go ever attempts to reach PostgreSQL, so
// no real database is needed to prove it.
func TestPasswordVaultMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex(t *testing.T) {
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-kms-check")

	cmd := exec.Command(vaultBin)
	cmd.Env = append(buildEnv(root), "PORT=18499", "DATABASE_URL=postgres://deliberately-unreachable/db", "SKIP_DEMO_SEED=1")
	var outBuf bytes.Buffer
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the process to exit non-zero (log.Fatalf) when DATABASE_URL is set without KMS_KEY_HEX")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("expected the process to exit quickly via log.Fatalf, but it was still running after 5s — did it start listening instead?\noutput so far:\n%s", outBuf.String())
	}

	if !strings.Contains(outBuf.String(), "KMS_KEY_HEX") {
		t.Fatalf("expected the fatal log message to mention KMS_KEY_HEX, got:\n%s", outBuf.String())
	}
}

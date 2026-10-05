// This file proves Password Vault's PostgreSQL-backed storage is real
// persistence: an account onboarded against one running password-vault
// process survives that process being killed and a brand new one
// started in its place, both pointed at the same database.
//
// Skipped, not failed, when TEST_DATABASE_URL is unset — see
// /NOTES_SANDBOX.md.
package integration_test

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

func TestPostgresFlow_AccountSurvivesPasswordVaultProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-pg")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-pg")

	authz := startService(t, root, authzBin, "18401")
	authzCreatePolicy(t, authz.baseURL, "vault-admin", "vault:account-admin:*", "allow")

	// Unique per run: the database persists across runs by design, so a
	// fixed id would collide with itself on the second execution.
	accountID := fmt.Sprintf("acc_pg_restart_%d", time.Now().UnixNano())
	const secretValue = "postgres-restart-it-secret"

	vault1 := startService(t, root, vaultBin, "18402", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "SKIP_DEMO_SEED=1")
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

	vault2 := startService(t, root, vaultBin, "18403", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "SKIP_DEMO_SEED=1")

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

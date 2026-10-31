package integration_test

// ADR-0044 across real processes and a real database: a session on a post_use account ends
// while the Vault is down. The Broker keeps the notice owed and sends it again; the Vault, back,
// records the debt and turns the secret on the target — once, as the system.

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func TestPostgresFlow_ARotationAfterUseIsNotLost_WhenTheVaultIsDownAtTheEndOfTheSession(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-44")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-44")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-44")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-44")

	authz := startService(t, root, authzBin, "18491")
	audit := startService(t, root, auditBin, "18492")
	spy := startAuditSpy(t, audit.baseURL)
	kms := testKMSKeyHex(t)
	vaultEnv := []string{"AUTHORIZATION_URL=" + authz.baseURL, "DATABASE_URL=" + dsn, "KMS_KEY_HEX=" + kms, "SKIP_DEMO_SEED=1", "AUDIT_URL=" + spy.baseURL}
	vault := startService(t, root, vaultBin, "18493", vaultEnv...)
	// The proxy only has to agree to cut the session.
	proxyURL := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/internal/v1/revoke-session" {
			_, _ = w.Write([]byte(`{"tickets_revoked":0,"connections_cut":0}`))
			return
		}
		http.NotFound(w, r)
	}))
	broker := startService(t, root, brokerBin, "18494", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL="+proxyURL, "SESSION_EXPIRY_SWEEP_SECONDS=1")

	run := fmt.Sprintf("%d", time.Now().UnixNano())
	rec, acc := "acc_au_rec_"+run, "acc_au_"+run
	tgt := startRotatableTarget(t, map[string]string{"root": "au-root-pw", "app": "au-old-pw"})
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "it-role", "vault:account:"+acc, "allow")
	for _, body := range []map[string]any{
		{"id": rec, "name": rec, "username": "root", "rotationPolicy": "manual", "initialSecret": []byte("au-root-pw")},
		{"id": acc, "name": acc, "username": "app", "rotationPolicy": "post_use", "initialSecret": []byte("au-old-pw"), "reconciliationAccountId": rec},
	} {
		body["targetHost"], body["protocol"], body["actorRoles"] = tgt.addr, "ssh", []string{"vault-admin"}
		if s := vaultOnboard(t, vault.baseURL, body); s != http.StatusCreated {
			t.Fatalf("onboard %v: %d", body["id"], s)
		}
	}
	sess, status := brokerCreateSession(t, broker.baseURL, []string{"it-role"}, acc)
	if status != http.StatusCreated {
		t.Fatalf("create session: %d", status)
	}

	// The Vault goes down; the session ends.
	_ = vault.cmd.Process.Kill()
	_ = vault.cmd.Wait()
	if s := brokerTerminateSession(t, broker.baseURL, sess.ID); s != http.StatusOK {
		t.Fatalf("terminate: %d", s)
	}
	time.Sleep(2 * time.Second)
	if tgt.password("app") != "au-old-pw" {
		t.Fatal("rotated with the Vault down")
	}

	// The Vault back, on the same base: the Broker tells it again, and it pays.
	startService(t, root, vaultBin, "18493", vaultEnv...)
	waitUntil(t, 100*time.Second, "the notice to be sent again and the secret rotated", func() bool { return tgt.password("app") != "au-old-pw" })
	spy.waitFor(t, "vault.rotate", acc, true)
	if canLogIn(tgt.addr, "app", "au-old-pw") {
		t.Fatal("the password used by the ended session still opens the target")
	}

	// Once, as the system — though the Broker may tell it again.
	time.Sleep(3 * time.Second)
	rotated := 0
	spy.mu.Lock()
	for _, e := range spy.events {
		if e.ResourceID == acc && e.Action == "vault.rotate" && e.Success {
			rotated++
		}
		if e.ResourceID == acc && strings.HasPrefix(e.Action, "vault.rotate") && e.ActorID != "" {
			t.Errorf("a rotation after use names %q", e.ActorID)
		}
	}
	spy.mu.Unlock()
	if rotated != 1 {
		t.Fatalf("%d rotations for one use", rotated)
	}
}

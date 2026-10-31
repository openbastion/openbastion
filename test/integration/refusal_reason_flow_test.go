package integration_test

// ADR-0042 across real processes: the operator who connects to a session on an account whose
// host key is not pinned is told so, through the Gateway, from the Vault's code; and when the
// Vault does not answer, the operator reads a 503 that names no address.

import (
	"context"
	"database/sql"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func gatewayConnectBody(t *testing.T, gatewayURL, token, sessionID string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, gatewayURL+"/sessions/"+sessionID+"/connect", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}

func TestPostgresFlow_TheOperatorIsToldWhyASessionCannotStart_AndNeverWhereAServiceIs(t *testing.T) {
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
	bins := map[string]string{}
	for name, pkg := range map[string]string{
		"vault": "./services/vault/password-vault/cmd/password-vault", "audit": "./services/recording-audit/audit-service/cmd/audit-service",
		"authz": "./services/access/authorization/cmd/authorization", "authn": "./services/access/authentication/cmd/authentication",
		"broker": "./services/access/session-broker/cmd/session-broker", "gateway": "./services/access/api-gateway/cmd/api-gateway",
	} {
		bins[name] = buildBinary(t, root, pkg, name+"-42")
	}
	audit := startService(t, root, bins["audit"], "18482")
	authz := startService(t, root, bins["authz"], "18483")
	vault := startService(t, root, bins["vault"], "18481", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL,
		"DATABASE_URL="+dsn, "KMS_KEY_HEX="+testKMSKeyHex(t), "SKIP_DEMO_SEED=1")
	authn := startService(t, root, bins["authn"], "18487", "SKIP_DEMO_SEED=1")
	// No proxy listens there: a session that got this far would fail — it must not get this far.
	broker := startService(t, root, bins["broker"], "18484", "AUTHORIZATION_URL="+authz.baseURL, "VAULT_URL="+vault.baseURL,
		"AUDIT_URL="+audit.baseURL, "SSH_PROXY_URL=http://127.0.0.1:18485")
	gateway := startService(t, root, bins["gateway"], "18488", "AUTHENTICATION_URL="+authn.baseURL, "SESSION_BROKER_URL="+broker.baseURL,
		"VAULT_URL="+vault.baseURL, "AUTHORIZATION_URL="+authz.baseURL)

	account := fmt.Sprintf("acc_unpinned_%d", time.Now().UnixNano())
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:"+account, "allow")
	if s := vaultOnboard(t, vault.baseURL, map[string]any{"id": account, "name": account, "username": "root", "targetHost": "10.0.0.42:22",
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte("x"), "actorRoles": []string{"vault-admin"}}); s != http.StatusCreated {
		t.Fatalf("onboard: %d", s)
	}
	// As an account onboarded before ADR-0039 is: no pinned key.
	if _, err := db.ExecContext(context.Background(), `UPDATE privileged_accounts SET host_key = '' WHERE id = $1`, account); err != nil {
		t.Fatal(err)
	}
	authCreateUser(t, authn.baseURL, "operator", "Operator", "op-password-123", []string{"dba"})
	token, _ := gatewayLogin(t, gateway.baseURL, "operator", "op-password-123")

	t.Run("an unpinned account: 409, and the operator reads what to do", func(t *testing.T) {
		sess, status := gatewayCreateSession(t, gateway.baseURL, token, "", nil, account)
		if status != http.StatusCreated {
			t.Fatalf("create: %d", status)
		}
		code, body := gatewayConnectBody(t, gateway.baseURL, token, sess.ID)
		if code != http.StatusConflict || !strings.Contains(body, "no pinned host key") || !strings.Contains(body, "host-key") {
			t.Fatalf("connect: %d %q", code, body)
		}
		if strings.Contains(body, "status 409") {
			t.Fatalf("the operator reads a status, not a reason: %q", body)
		}
	})

	t.Run("the Vault down: 503, and no address in what the operator reads", func(t *testing.T) {
		sess, status := gatewayCreateSession(t, gateway.baseURL, token, "", nil, account)
		if status != http.StatusCreated {
			t.Fatalf("create: %d", status)
		}
		_ = vault.cmd.Process.Kill()
		_ = vault.cmd.Wait()
		code, body := gatewayConnectBody(t, gateway.baseURL, token, sess.ID)
		if code != http.StatusServiceUnavailable || strings.Contains(body, "127.0.0.1") || strings.Contains(body, "18481") || strings.Contains(body, "dial tcp") {
			t.Fatalf("connect with the Vault down: %d %q", code, body)
		}
	})
}

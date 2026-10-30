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
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"

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

// testSigningKeyHex generates a fresh random 32-byte HMAC key, hex-
// encoded, for TOKEN_SIGNING_KEY_HEX — same rationale as testKMSKeyHex
// above: cmd/authentication/main.go now refuses to start with
// DATABASE_URL set but no TOKEN_SIGNING_KEY_HEX, since a process-random
// signing key would invalidate every token the moment the process
// restarts (see infrastructure.SigningKeyFromHex's doc comment and
// NOTES_SANDBOX.md).
func testSigningKeyHex(t *testing.T) string {
	t.Helper()
	var key [32]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatalf("generating test signing key: %v", err)
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

	// A rotation reaches the target and is audited (ADR-0037): a target that takes chpasswd,
	// the account's reconciliation account on it, and an Audit Service.
	tgt := startRotatableTarget(t, map[string]string{"root": "pg-restart-root-pw", "app": secretValue})
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-pg-vault")
	audit := startService(t, root, auditBin, "18409")
	vault1 := startService(t, root, vaultBin, "18402", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kmsKeyHex, "SKIP_DEMO_SEED=1", "AUDIT_URL="+audit.baseURL)
	if s := vaultOnboard(t, vault1.baseURL, map[string]any{"id": accountID + "_rec", "name": "rec", "username": "root", "targetHost": tgt.addr,
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte("pg-restart-root-pw"), "actorRoles": []string{"vault-admin"}}); s != http.StatusCreated {
		t.Fatalf("onboard the reconciliation account: %d", s)
	}
	if s := vaultOnboard(t, vault1.baseURL, map[string]any{"id": accountID, "name": accountID, "username": "app", "targetHost": tgt.addr,
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(secretValue), "actorRoles": []string{"vault-admin"},
		"reconciliationAccountId": accountID + "_rec"}); s != http.StatusCreated {
		t.Fatalf("onboard: %d", s)
	}

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

	vault2 := startService(t, root, vaultBin, "18403", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kmsKeyHex, "SKIP_DEMO_SEED=1", "AUDIT_URL="+audit.baseURL)

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
		if tgt.password("app") != rotated {
			t.Fatal("the secret the restarted Vault injects is not the one the target takes")
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

// authLogin and authVerify call Authentication's own HTTP API directly
// (not through the Gateway) — this file's restart tests only need to
// prove persistence of Authentication's own state, not the Gateway's
// identity-injection behavior, which is already covered elsewhere
// (gateway_flow_test.go, admin_routes_test.go).
func authLogin(t *testing.T, baseURL, username, password string) (token string, status int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(baseURL+"/auth/v1/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", resp.StatusCode
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode login response: %v", err)
	}
	return out.AccessToken, resp.StatusCode
}

func authVerify(t *testing.T, baseURL, token string) (userID, username string, roles []string, status int) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := http.Post(baseURL+"/auth/v1/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, resp.StatusCode
	}
	var out struct {
		UserID   string   `json:"userId"`
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode verify response: %v", err)
	}
	return out.UserID, out.Username, out.Roles, resp.StatusCode
}

// TestPostgresFlow_UserAndSigningKeySurviveAuthenticationProcessRestart
// proves Authentication's half of this increment, and closes the same
// class of gap LocalKMS had (NOTES_SANDBOX.md): a user onboarded against
// one process, and a token issued by that SAME process, must both still
// work against a second, independent process restarted on the same
// database — the user via PostgreSQL, the token's signature via
// TOKEN_SIGNING_KEY_HEX supplied to both processes identically (never
// derived from the database itself, exactly like KMS_KEY_HEX).
func TestPostgresFlow_UserAndSigningKeySurviveAuthenticationProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	authBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-pg")

	signingKeyHex := testSigningKeyHex(t) // shared across both processes below
	username := fmt.Sprintf("pg_restart_user_%d", time.Now().UnixNano())
	const password = "pg-restart-password-123"

	auth1 := startService(t, root, authBin, "18431", "DATABASE_URL="+dsn, "TOKEN_SIGNING_KEY_HEX="+signingKeyHex, "SKIP_DEMO_SEED=1")
	authCreateUser(t, auth1.baseURL, username, "PG Restart User", password, []string{"dba"})

	token, status := authLogin(t, auth1.baseURL, username, password)
	if status != http.StatusOK {
		t.Fatalf("login against first process: status %d", status)
	}

	// The process that onboarded the user and issued the token is gone —
	// both the user row and the ability to verify that exact token must
	// now depend entirely on PostgreSQL and TOKEN_SIGNING_KEY_HEX, not on
	// anything held in that process's memory.
	stopService(t, auth1)

	auth2 := startService(t, root, authBin, "18432", "DATABASE_URL="+dsn, "TOKEN_SIGNING_KEY_HEX="+signingKeyHex, "SKIP_DEMO_SEED=1")

	t.Run("a token issued by the first process verifies against the second, restarted process", func(t *testing.T) {
		userID, verifiedUsername, roles, status := authVerify(t, auth2.baseURL, token)
		if status != http.StatusOK {
			t.Fatalf("verify on restarted process: status %d — TOKEN_SIGNING_KEY_HEX did not survive the restart", status)
		}
		if verifiedUsername != username || len(roles) != 1 || roles[0] != "dba" || userID == "" {
			t.Fatalf("unexpected verified claims: userID=%q username=%q roles=%v", userID, verifiedUsername, roles)
		}
	})

	t.Run("the user onboarded on the first process can log in again on the restarted process", func(t *testing.T) {
		if _, status := authLogin(t, auth2.baseURL, username, password); status != http.StatusOK {
			t.Fatalf("login on restarted process: status %d — the user did not survive the restart via PostgreSQL", status)
		}
	})
}

// TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart proves
// Audit Service's half of this increment: an event emitted by one
// process must correctly chain off of it from a second, independent
// process restarted on the same database — EmitEvent's hash chaining
// (audit_service.go) depends on Last() seeing the true, current tail of
// the chain, not whatever a given process happens to remember.
func TestPostgresFlow_EventChainSurvivesAuditServiceProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	// VerifyChain (audit_service.go) walks the ENTIRE audit_events table
	// from the very first row, unlike Count()/ForRoles() elsewhere in
	// this project — any row written directly by
	// postgres_store_test.go's infrastructure-level tests (which Append
	// literal, non-computed hash values on purpose, to exercise the
	// Store interface in isolation from the hashing logic) would
	// otherwise make VerifyChain report tampering on data this test
	// never wrote. Truncating first makes this test deterministic
	// regardless of what ran against this database before it — the same
	// practical limitation as the TRUNCATE already documented in
	// NOTES_SANDBOX.md for Count()-based assertions, just with a lower
	// tolerance: a hash chain breaks forever on a single bad row, where
	// a count only breaks one assertion.
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("opening database for setup: %v", err)
	}
	defer db.Close()
	if _, err := db.Exec("TRUNCATE audit_events RESTART IDENTITY"); err != nil {
		t.Fatalf("truncating audit_events before the test: %v", err)
	}

	root := repoRoot(t)
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-pg")
	// One chain key for both processes (ADR-0027): the second verifies what the first signed.
	chainKey := testKMSKeyHex(t)
	// And one anchor file, outside the database (ADR-0028).
	anchorFile := t.TempDir() + "/anchors.jsonl"

	audit1 := startService(t, root, auditBin, "18421", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+chainKey, "AUDIT_ANCHOR_FILE="+anchorFile)
	emitter1 := &httpAuditEmitter{baseURL: audit1.baseURL}
	if err := emitter1.EmitEvent(context.Background(), "session.connect", "session", "sess-pg-restart", true); err != nil {
		t.Fatalf("EmitEvent on first process: %v", err)
	}

	// The process that emitted the first event is gone — the second
	// process's next event must chain off of PostgreSQL's view of the
	// tail, not an empty in-process memory that would make it look like
	// the start of a brand new, disconnected chain.
	stopService(t, audit1)

	audit2 := startService(t, root, auditBin, "18422", "DATABASE_URL="+dsn, "AUDIT_CHAIN_KEY_HEX="+chainKey, "AUDIT_ANCHOR_FILE="+anchorFile)
	emitter2 := &httpAuditEmitter{baseURL: audit2.baseURL}
	if err := emitter2.EmitEvent(context.Background(), "session.terminate", "session", "sess-pg-restart", true); err != nil {
		t.Fatalf("EmitEvent on second, restarted process: %v", err)
	}

	resp, err := http.Get(audit2.baseURL + "/audit/v1/verify-chain")
	if err != nil {
		t.Fatalf("verify-chain: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("verify-chain: status %d — the second process's event did not correctly chain off the first process's last event via PostgreSQL", resp.StatusCode)
	}
}

type sessionDetails struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	Protocol            string `json:"protocol"`
	RequestedBy         string `json:"requestedBy"`
	PrivilegedAccountID string `json:"privilegedAccountId"`
	Justification       string `json:"justification"`
}

// brokerGetSession reads a session as its requester (ADR-0019: the Broker is told who
// reads by the Gateway; here the test plays the Gateway, as brokerCreateSession does).
func brokerGetSession(t *testing.T, baseURL, id string) (*sessionDetails, int) {
	t.Helper()
	resp, err := http.Get(baseURL + "/sessions/" + id + "?callerId=it-user1&actorRoles=dba")
	if err != nil {
		t.Fatalf("get-session: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out sessionDetails
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode get-session response: %v", err)
	}
	return &out, resp.StatusCode
}

// TestPostgresFlow_SessionSurvivesSessionBrokerProcessRestart proves
// Session Broker's half of this increment. CreateSession and GetSession
// need only Authorization (CheckAccess) and Audit (EmitEvent) — Vault
// and the proxy are only ever reached by Connect, which this test never
// calls — so VAULT_URL below deliberately points nowhere real; a live
// Vault is not needed to prove a session survives a Session Broker
// restart via PostgreSQL. The terminate at the end does reach the proxy
// (ADR-0018: ending a session is telling the proxy first), so the proxy
// is a stand-in that confirms the revocation; the real one is the
// subject of session_revocation_test.go.
func TestPostgresFlow_SessionSurvivesSessionBrokerProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-broker-pg")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-broker-pg")
	brokerBin := buildBinary(t, root, "./services/access/session-broker/cmd/session-broker", "session-broker-pg")

	authz := startService(t, root, authzBin, "18441")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "dba", "vault:account:*", "allow")
	audit := startService(t, root, auditBin, "18442") // in-memory is fine — this test only cares about session persistence

	accountID := fmt.Sprintf("acc_pg_broker_restart_%d", time.Now().UnixNano())
	unreachable := "http://127.0.0.1:1" // Connect is never called in this test
	proxyURL := newLocalServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/internal/v1/revoke-session" {
			_, _ = w.Write([]byte(`{"tickets_revoked":0,"connections_cut":0}`))
			return
		}
		http.NotFound(w, r)
	}))

	broker1 := startService(t, root, brokerBin, "18443",
		"AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL,
		"VAULT_URL="+unreachable, "SSH_PROXY_URL="+proxyURL, "DATABASE_URL="+dsn)

	sess, status := brokerCreateSession(t, broker1.baseURL, []string{"dba"}, accountID)
	if status != http.StatusCreated {
		t.Fatalf("create-session on first process: status %d", status)
	}

	// The process that created the session is gone — it must live in the
	// database, not in that process's memory.
	stopService(t, broker1)

	broker2 := startService(t, root, brokerBin, "18444",
		"AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL,
		"VAULT_URL="+unreachable, "SSH_PROXY_URL="+proxyURL, "DATABASE_URL="+dsn)

	got, status := brokerGetSession(t, broker2.baseURL, sess.ID)
	if status != http.StatusOK {
		t.Fatalf("get-session on restarted process: status %d — the session did not survive the restart via PostgreSQL", status)
	}
	if got.Status != "active" || got.RequestedBy != "it-user1" || got.PrivilegedAccountID != accountID {
		t.Fatalf("unexpected session after restart: %+v", got)
	}

	t.Run("terminating on the restarted process is itself an UPSERT that persists", func(t *testing.T) {
		if status := brokerTerminateSession(t, broker2.baseURL, sess.ID); status != http.StatusOK {
			t.Fatalf("terminate-session: status %d", status)
		}
		got, status := brokerGetSession(t, broker2.baseURL, sess.ID)
		if status != http.StatusOK {
			t.Fatalf("get-session after terminate: status %d", status)
		}
		if got.Status != "terminated" {
			t.Fatalf("expected status %q after terminate, got %q", "terminated", got.Status)
		}
	})
}

// -- Command Recorder ------------------------------------------------------

func recorderPostEntries(t *testing.T, baseURL string, entries []map[string]any) (status int, received int) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"entries": entries})
	resp, err := http.Post(baseURL+"/recorder/v1/command-entries", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("post command-entries: %v", err)
	}
	defer resp.Body.Close()
	var out struct {
		EntriesReceived int `json:"entries_received"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.EntriesReceived
}

func recorderGetCommands(t *testing.T, baseURL, sessionID, actorRoles string) (int, recordingPage) {
	t.Helper()
	status, page, _ := recorderGetCommandsRaw(t, baseURL, sessionID, actorRoles)
	return status, page
}

// recorderGetCommandsRaw also returns the raw response body, for assertions
// about what an error response does and does not contain.
func recorderGetCommandsRaw(t *testing.T, baseURL, sessionID, actorRoles string) (int, recordingPage, string) {
	t.Helper()
	// The Recorder is called here as the Gateway calls it: with the user who reads, without
	// whom nothing is served (ADR-0022), and the roles of their token.
	resp, err := http.Get(baseURL + "/recorder/v1/sessions/" + sessionID + "/commands?callerId=u_pg_auditor&actorRoles=" + actorRoles)
	if err != nil {
		t.Fatalf("get commands: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	var page recordingPage
	if resp.StatusCode == http.StatusOK {
		_ = json.Unmarshal(raw, &page)
	}
	return resp.StatusCode, page, string(raw)
}

// TestCommandRecorderMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex is the
// Command Recorder's twin of the Vault check above: recordings must outlive the
// process, so with a database configured there is no random per-process key to
// fall back on — the process must refuse to start. Unconditional, for the same
// reason: the check runs before any database is contacted.
func TestCommandRecorderMain_RefusesToStartWithDatabaseURLButNoKMSKeyHex(t *testing.T) {
	root := repoRoot(t)
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-kek-check")

	cmd := exec.Command(recorderBin)
	cmd.Env = append(buildEnv(root), "PORT=18498", "DATABASE_URL=postgres://deliberately-unreachable/db")
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
			t.Fatal("expected a non-zero exit when DATABASE_URL is set without KMS_KEY_HEX")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("the process was still running after 5s — it must refuse to start without a key\noutput so far:\n%s", outBuf.String())
	}
	if !strings.Contains(outBuf.String(), "KMS_KEY_HEX") {
		t.Fatalf("expected the fatal message to name KMS_KEY_HEX, got:\n%s", outBuf.String())
	}

	// A malformed key is refused just the same, rather than silently weakened.
	cmd = exec.Command(recorderBin)
	cmd.Env = append(buildEnv(root), "PORT=18498", "DATABASE_URL=postgres://deliberately-unreachable/db", "KMS_KEY_HEX=abcd")
	outBuf.Reset()
	cmd.Stdout = &outBuf
	cmd.Stderr = &outBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	done = make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected a non-zero exit for a key that is not 32 bytes")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		t.Fatalf("a malformed KMS_KEY_HEX did not stop the process\noutput so far:\n%s", outBuf.String())
	}
}

func TestPostgresFlow_RecordingSurvivesCommandRecorderProcessRestart(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}

	root := repoRoot(t)
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-recorder-pg")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-pg")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-recorder-pg")

	authz := startService(t, root, authzBin, "18450")
	// Every read of a recording is written to the audit before it is served (ADR-0022);
	// in-memory is fine — this test only cares about the recording's persistence.
	audit := startService(t, root, auditBin, "18454")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "session-auditor", "recording:session:*", "allow")

	sessionID := fmt.Sprintf("sess_pg_recorder_restart_%d", time.Now().UnixNano())
	t0 := time.Now().UTC().Truncate(time.Microsecond)

	// One KEK for both processes, like the Vault test: a restarted recorder
	// can only read what its predecessor sealed if it is given the same key.
	kekHex := testKMSKeyHex(t)

	const secretCommand = "mysql -pCorrectHorseBatteryStaple-it"
	recorder1 := startService(t, root, recorderBin, "18451", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kekHex, "AUDIT_URL="+audit.baseURL)
	status, received := recorderPostEntries(t, recorder1.baseURL, []map[string]any{
		{"session_id": sessionID, "ts": t0, "command": "uptime"},
		// A NUL byte is valid JSON; the recorder strips it so a recording
		// never holds a byte that breaks text tooling downstream.
		{"session_id": sessionID, "ts": t0.Add(time.Second), "command": "ab\u0000cd"},
		{"session_id": sessionID, "ts": t0.Add(2 * time.Second), "command": "df -h"},
		{"session_id": sessionID, "ts": t0.Add(3 * time.Second), "command": secretCommand},
	})
	if status != http.StatusAccepted || received != 4 {
		t.Fatalf("post on first process: status %d, received %d", status, received)
	}

	// The process that stored the entries is gone — they must live in the
	// database, not in that process's memory.
	stopService(t, recorder1)

	recorder2 := startService(t, root, recorderBin, "18452", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+kekHex, "AUDIT_URL="+audit.baseURL)
	status, page := recorderGetCommands(t, recorder2.baseURL, sessionID, "session-auditor")
	if status != http.StatusOK {
		t.Fatalf("read on restarted process: status %d — the recording did not survive the restart via PostgreSQL", status)
	}
	got := page.commands()
	if page.TotalEntries != 4 || len(got) != 4 || got[0] != "uptime" || got[1] != "abcd" || got[2] != "df -h" || got[3] != secretCommand {
		t.Fatalf("unexpected recording after restart: total=%d %q", page.TotalEntries, got)
	}

	t.Run("the database holds no readable command, only a wrapped key and sealed rows", func(t *testing.T) {
		db, err := sql.Open("postgres", dsn)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		defer db.Close()

		rows, err := db.Query(`SELECT command_sealed FROM session_command_entries WHERE session_id = $1`, sessionID)
		if err != nil {
			t.Fatalf("select sealed rows: %v", err)
		}
		defer rows.Close()
		n := 0
		for rows.Next() {
			var sealed []byte
			if err := rows.Scan(&sealed); err != nil {
				t.Fatalf("scan: %v", err)
			}
			n++
			for _, readable := range []string{"CorrectHorseBatteryStaple", "mysql", "uptime", "df -h"} {
				if bytes.Contains(sealed, []byte(readable)) {
					t.Fatalf("a stored row contains %q in the clear", readable)
				}
			}
		}
		if n != 4 {
			t.Fatalf("expected 4 sealed rows in the database, got %d", n)
		}

		var wrapped []byte
		if err := db.QueryRow(`SELECT wrapped_dek FROM session_recording_keys WHERE session_id = $1`, sessionID).Scan(&wrapped); err != nil {
			t.Fatalf("no wrapped key stored for the session: %v", err)
		}
		if bytes.Contains(wrapped, []byte(kekHex)) {
			t.Fatal("the KEK itself is in the database")
		}
	})

	t.Run("a recorder started with the wrong key fails the read, it does not return garbage", func(t *testing.T) {
		wrong := startService(t, root, recorderBin, "18453", "AUTHORIZATION_URL="+authz.baseURL, "DATABASE_URL="+dsn, "KMS_KEY_HEX="+testKMSKeyHex(t), "AUDIT_URL="+audit.baseURL)
		status, page, body := recorderGetCommandsRaw(t, wrong.baseURL, sessionID, "session-auditor")
		if status != http.StatusInternalServerError {
			t.Fatalf("expected 500 from a recorder holding the wrong key, got %d with %q", status, page.commands())
		}
		if strings.Contains(body, "CorrectHorseBatteryStaple") || strings.Contains(body, "uptime") {
			t.Fatalf("the error response leaks recording content: %s", body)
		}

		// Nor may it extend the recording under a second, unreadable key.
		appendStatus, _ := recorderPostEntries(t, wrong.baseURL, []map[string]any{
			{"session_id": sessionID, "ts": t0.Add(10 * time.Second), "command": "must-not-be-stored"},
		})
		if appendStatus != http.StatusInternalServerError {
			t.Fatalf("expected 500 when appending with the wrong key, got %d", appendStatus)
		}
		// The right recorder is unaffected.
		if status, page := recorderGetCommands(t, recorder2.baseURL, sessionID, "session-auditor"); status != http.StatusOK || page.TotalEntries != 4 {
			t.Fatalf("the right recorder must still read 4 entries: status %d total %d", status, page.TotalEntries)
		}
	})

	t.Run("a role without recording:session:read is still refused after the restart", func(t *testing.T) {
		if status, _ := recorderGetCommands(t, recorder2.baseURL, sessionID, "dba"); status != http.StatusForbidden {
			t.Fatalf("expected 403, got %d", status)
		}
	})

	t.Run("a batch with one invalid entry is refused whole and stores nothing", func(t *testing.T) {
		other := sessionID + "_refused"
		status, _ := recorderPostEntries(t, recorder2.baseURL, []map[string]any{
			{"session_id": other, "ts": t0, "command": "valid-but-must-not-be-kept"},
			{"session_id": "", "ts": t0, "command": "no session"},
		})
		if status != http.StatusBadRequest {
			t.Fatalf("expected 400, got %d", status)
		}
		if _, page := recorderGetCommands(t, recorder2.baseURL, other, "session-auditor"); page.TotalEntries != 0 {
			t.Fatalf("part of a refused batch was stored: %q", page.commands())
		}
	})
}

package integration_test

// ADR-0049 against a real OpenBao (its Transit engine, in a container) and real processes on a real
// PostgreSQL: the Vault seals new secrets under the Transit key, with a token that may only encrypt
// and decrypt with that key; what was sealed under KMS_KEY_HEX before stays readable while that key
// is given, and is refused once it is not; Transit unreachable, nothing sealed under it is sealed or
// opened; a configuration Transit would not honour stops the Vault and the Command Recorder.

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/transit"
)

// openBaoImage is pinned by its index digest, like every image the project runs (ADR-0047).
const openBaoImage = "openbao/openbao@sha256:5046911075e137e154ce49ab051502f4ec7cf367d484ae4a4dce665d9b90561f" // v2.7.2

type openBao struct {
	addr, name  string
	createToken func(t *testing.T, period string) string // a token of the key's policy; periodic if period is set
	revoke      func(t *testing.T, token string)
}

// startOpenBao runs OpenBao in development mode, mounts Transit, creates key, and returns the
// server with a token file whose token may only encrypt and decrypt with that key.
func startOpenBao(t *testing.T, key string) (*openBao, string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed — skipping the test against a real OpenBao")
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	b := &openBao{addr: fmt.Sprintf("http://127.0.0.1:%d", port), name: fmt.Sprintf("obao-test-%d", time.Now().UnixNano())}
	const root = "integration-root-token"
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", b.name, "-p", fmt.Sprintf("127.0.0.1:%d:8200", port),
		"-e", "BAO_DEV_ROOT_TOKEN_ID="+root, openBaoImage, "server", "-dev", "-dev-listen-address=0.0.0.0:8200").CombinedOutput(); err != nil {
		t.Skipf("cannot start OpenBao (%v): %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", b.name).Run() })
	waitUntil(t, 30*time.Second, "OpenBao to answer", func() bool {
		resp, err := http.Get(b.addr + "/v1/sys/health")
		if err == nil {
			resp.Body.Close()
		}
		return err == nil && resp.StatusCode == http.StatusOK
	})
	call := func(method, path string, body any) map[string]any {
		t.Helper()
		raw, _ := json.Marshal(body)
		req, _ := http.NewRequest(method, b.addr+path, bytes.NewReader(raw))
		req.Header.Set("X-Vault-Token", root)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 300 {
			t.Fatalf("OpenBao %s %s: %d", method, path, resp.StatusCode)
		}
		var out map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&out)
		return out
	}
	call(http.MethodPost, "/v1/sys/mounts/transit", map[string]string{"type": "transit"})
	call(http.MethodPost, "/v1/transit/keys/"+key, map[string]string{"type": "aes256-gcm96"})
	call(http.MethodPost, "/v1/transit/keys/other-key", map[string]string{"type": "aes256-gcm96"})
	// The documented minimal policy (docs/security/key-management.md): the key both ways, and the
	// token's own life (ADR-0053).
	policy := fmt.Sprintf(`path "transit/encrypt/%s" { capabilities = ["update"] }
path "transit/decrypt/%s" { capabilities = ["update"] }
path "auth/token/lookup-self" { capabilities = ["read"] }
path "auth/token/renew-self" { capabilities = ["update"] }`, key, key)
	call(http.MethodPut, "/v1/sys/policies/acl/openbastion-"+key, map[string]string{"policy": policy})
	b.createToken = func(t *testing.T, period string) string {
		t.Helper()
		req := map[string]any{"policies": []string{"openbastion-" + key}, "ttl": "1h", "no_default_policy": true}
		if period != "" {
			req = map[string]any{"policies": []string{"openbastion-" + key}, "period": period, "no_default_policy": true}
		}
		tok := call(http.MethodPost, "/v1/auth/token/create", req)
		return writeToken(t, tok["auth"].(map[string]any)["client_token"].(string), 0o600)
	}
	b.revoke = func(t *testing.T, token string) {
		t.Helper()
		call(http.MethodPost, "/v1/auth/token/revoke", map[string]string{"token": token})
	}
	return b, b.createToken(t, "")
}

func writeToken(t *testing.T, token string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "transit-token")
	if err := os.WriteFile(p, []byte(token+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func (b *openBao) pause(t *testing.T, paused bool) {
	t.Helper()
	cmd := "unpause"
	if paused {
		cmd = "pause"
	}
	if out, err := exec.Command("docker", cmd, b.name).CombinedOutput(); err != nil {
		t.Fatalf("docker %s: %v %s", cmd, err, out)
	}
}

// fetchSecret is the Broker's then the proxy's call for one session: the secret, or why not.
func fetchSecret(t *testing.T, vaultURL, accountID string) (string, error) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{"session_id": "session_" + accountID + fmt.Sprint(time.Now().UnixNano()), "privileged_account_id": accountID,
		"proxy_service_id": "ssh-proxy", "ttl_seconds": 60})
	resp, err := http.Post(vaultURL+"/vault/v1/authorize-scope", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	var scope struct {
		ScopeToken string `json:"scope_token"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&scope)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || scope.ScopeToken == "" {
		return "", fmt.Errorf("authorize-scope: %d", resp.StatusCode)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	f, err := (&httpVaultClient{baseURL: vaultURL}).FetchCredential(ctx, scope.ScopeToken, "ssh-proxy")
	if err != nil {
		return "", err
	}
	return string(f.Material), nil
}

func TestPostgresFlow_TransitKeepsTheKeys_WhatWasSealedBeforeStaysReadable(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	bao, tokenFile := startOpenBao(t, "openbastion-vault")
	root := repoRoot(t)
	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-49")
	recorderBin := buildBinary(t, root, "./services/recording-audit/command-recorder/cmd/command-recorder", "command-recorder-49")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-49")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-49")
	authz := startService(t, root, authzBin, "19741")
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	kms := testKMSKeyHex(t)
	withTransit := func(extra ...string) []string {
		return append([]string{"TRANSIT_ADDR=" + bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE=" + tokenFile}, extra...)
	}
	vaultEnv := func(extra ...string) []string {
		return append([]string{"AUTHORIZATION_URL=" + authz.baseURL, "DATABASE_URL=" + dsn, "SKIP_DEMO_SEED=1"}, extra...)
	}
	run := fmt.Sprint(time.Now().UnixNano())
	before, after := "acc_before_transit_"+run, "acc_after_transit_"+run
	onboard := func(vaultURL, id, secret string) int {
		return vaultOnboard(t, vaultURL, map[string]any{"id": id, "name": id, "username": "root", "targetHost": "10.0.0.9:22",
			"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(secret), "actorRoles": []string{"vault-admin"}})
	}
	keyIDOf := func(id string) (keyID string, material []byte) {
		t.Helper()
		if err := db.QueryRow(`SELECT encryption_key_id, encrypted_material FROM vault_secrets WHERE privileged_account_id = $1 ORDER BY version DESC LIMIT 1`, id).Scan(&keyID, &material); err != nil {
			t.Fatal(err)
		}
		return keyID, material
	}

	// Before Transit: the local key.
	v1 := startService(t, root, vaultBin, "19742", vaultEnv("KMS_KEY_HEX="+kms)...)
	if s := onboard(v1.baseURL, before, "secret-sealed-before"); s != http.StatusCreated {
		t.Fatalf("onboard before: %d", s)
	}
	stopService(t, v1)

	t.Run("a configuration Transit would not honour stops the Vault and the Recorder, without the token in the message", func(t *testing.T) {
		token, _ := os.ReadFile(tokenFile)
		cases := map[string][]string{
			"the address without the key nor the token": {"TRANSIT_ADDR=" + bao.addr},
			"a token others can read":                   {"TRANSIT_ADDR=" + bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE=" + writeToken(t, strings.TrimSpace(string(token)), 0o644)},
			"a token Transit refuses":                   {"TRANSIT_ADDR=" + bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE=" + writeToken(t, "s.not-a-real-token", 0o600)},
			"a key the token may not use":               {"TRANSIT_ADDR=" + bao.addr, "TRANSIT_KEY=other-key", "TRANSIT_TOKEN_FILE=" + tokenFile},
			"a key that does not exist":                 {"TRANSIT_ADDR=" + bao.addr, "TRANSIT_KEY=no-such-key", "TRANSIT_TOKEN_FILE=" + tokenFile},
			"http to a host that is not local":          {"TRANSIT_ADDR=http://openbao.example:8200", "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE=" + tokenFile},
		}
		for name, env := range cases {
			for bin, port := range map[string]string{vaultBin: "19743", recorderBin: "19744"} {
				out := runUntilExit(t, root, bin, append(vaultEnv("PORT="+port, "AUDIT_URL=http://127.0.0.1:1"), env...)...)
				if !strings.Contains(out, "TRANSIT") && !strings.Contains(out, "Transit") {
					t.Fatalf("%s (%s): the refusal does not name Transit:\n%s", name, filepath.Base(bin), out)
				}
				if strings.Contains(out, strings.TrimSpace(string(token))) {
					t.Fatalf("%s (%s): the token is in the output", name, filepath.Base(bin))
				}
			}
		}
	})

	v2 := startService(t, root, vaultBin, "19745", vaultEnv(withTransit("KMS_KEY_HEX="+kms)...)...)
	t.Run("with Transit and the old key: new secrets go to Transit, the old ones are still read", func(t *testing.T) {
		if s := onboard(v2.baseURL, after, "secret-sealed-after"); s != http.StatusCreated {
			t.Fatalf("onboard after: %d", s)
		}
		if id, _ := keyIDOf(before); id != "local-dev-key-v1" {
			t.Fatalf("the old secret names %q", id)
		}
		id, material := keyIDOf(after)
		if id != "transit:transit/openbastion-vault" || bytes.Contains(material, []byte("secret-sealed-after")) || !bytes.HasPrefix(material, []byte("OBT1")) {
			t.Fatalf("the new secret: key %q, material %q", id, material)
		}
		for acc, want := range map[string]string{before: "secret-sealed-before", after: "secret-sealed-after"} {
			if got, err := fetchSecret(t, v2.baseURL, acc); err != nil || got != want {
				t.Fatalf("%s: %q, %v", acc, got, err)
			}
		}
	})

	t.Run("Transit unreachable: nothing sealed under it is opened, nothing new is sealed; back, everything is", func(t *testing.T) {
		bao.pause(t, true)
		resumed := false
		defer func() {
			if !resumed {
				bao.pause(t, false)
			}
		}()
		if _, err := fetchSecret(t, v2.baseURL, after); err == nil || !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("a secret sealed under Transit, Transit unreachable: %v, want a 503", err)
		}
		if s := onboard(v2.baseURL, "acc_during_outage_"+run, "x"); s != http.StatusServiceUnavailable {
			t.Fatalf("onboarding with Transit unreachable: %d, want 503", s)
		}
		// What the local key sealed does not depend on Transit.
		if got, err := fetchSecret(t, v2.baseURL, before); err != nil || got != "secret-sealed-before" {
			t.Fatalf("the old secret with Transit down: %q, %v", got, err)
		}
		bao.pause(t, false)
		resumed = true
		if got, err := fetchSecret(t, v2.baseURL, after); err != nil || got != "secret-sealed-after" {
			t.Fatalf("Transit back: %q, %v", got, err)
		}
	})
	stopService(t, v2)

	t.Run("with Transit alone: the old secret is refused, the new one read", func(t *testing.T) {
		v3 := startService(t, root, vaultBin, "19746", vaultEnv(withTransit()...)...)
		if _, err := fetchSecret(t, v3.baseURL, before); err == nil || !strings.Contains(err.Error(), "status 503") {
			t.Fatalf("a secret sealed under a key the Vault no longer holds: %v, want a 503 (a key missing, not a refusal)", err)
		}
		if got, err := fetchSecret(t, v3.baseURL, after); err != nil || got != "secret-sealed-after" {
			t.Fatalf("the new secret: %q, %v", got, err)
		}
	})

	t.Run("the token can do nothing but encrypt and decrypt with its key", func(t *testing.T) {
		c, err := transit.New(transit.Config{Addr: bao.addr, Key: "other-key", TokenFile: tokenFile})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Encrypt(context.Background(), []byte("x"), []byte("a")); err == nil || !strings.Contains(err.Error(), "403") {
			t.Fatalf("the token wrapped with another key: %v", err)
		}
	})

	t.Run("a periodic token outlives its period: the Vault renews it at half its life (ADR-0053)", func(t *testing.T) {
		short := bao.createToken(t, "4s")
		v5 := startService(t, root, vaultBin, "19748", vaultEnv("TRANSIT_ADDR="+bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE="+short)...)
		time.Sleep(10 * time.Second) // two and a half periods: without a renewal, the token has ended
		if got, err := fetchSecret(t, v5.baseURL, after); err != nil || got != "secret-sealed-after" {
			t.Fatalf("after 10 s with a 4 s periodic token: %q, %v", got, err)
		}
		if !strings.Contains(v5.out.String(), "renewed at half its life") {
			t.Fatalf("the Vault does not say it renews its token:\n%s", v5.out.String())
		}
	})

	t.Run("ADR-0055: with both keys, what the local key protects is re-sealed under Transit; then Transit alone reads it", func(t *testing.T) {
		// Each re-seal is written to the audit before it is made: the Vault needs one.
		audit := startService(t, root, auditBin, "19751")
		spy := startAuditSpy(t, audit.baseURL)
		v6 := startService(t, root, vaultBin, "19749", vaultEnv(withTransit("KMS_KEY_HEX="+kms, "KEY_REWRAP_SWEEP_SECONDS=1", "AUDIT_URL="+spy.baseURL)...)...)
		deadline := time.Now().Add(30 * time.Second)
		for {
			if id, _ := keyIDOf(before); id == "transit:transit/openbastion-vault" {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("the old secret was not re-sealed under Transit in 30 s; the Vault said:\n%s", v6.out.String())
			}
			time.Sleep(200 * time.Millisecond)
		}
		spy.waitFor(t, "vault.secret_rewrapped", before, true)
		if _, material := keyIDOf(before); !bytes.HasPrefix(material, []byte("OBT1")) || bytes.Contains(material, []byte("secret-sealed-before")) {
			t.Fatalf("the re-sealed secret is not a Transit envelope: %q", material)
		}
		if out := v6.out.String(); !strings.Contains(out, "re-sealed under the current key") {
			t.Fatalf("the Vault does not say it re-seals:\n%s", out)
		}
		stopService(t, v6)
		v7 := startService(t, root, vaultBin, "19750", vaultEnv(withTransit()...)...)
		if got, err := fetchSecret(t, v7.baseURL, before); err != nil || got != "secret-sealed-before" {
			t.Fatalf("Transit alone, after the rewrap: %q, %v", got, err)
		}
	})

	t.Run("ADR-0056: a token replaced on disk is taken, and the old one can then be revoked", func(t *testing.T) {
		file := bao.createToken(t, "")
		old, _ := os.ReadFile(file)
		v8 := startService(t, root, vaultBin, "19752", vaultEnv("TRANSIT_ADDR="+bao.addr, "TRANSIT_KEY=openbastion-vault", "TRANSIT_TOKEN_FILE="+file, "TRANSIT_TOKEN_RELOAD_SECONDS=1")...)
		fresh, _ := os.ReadFile(bao.createToken(t, ""))
		if err := os.WriteFile(file, fresh, 0o600); err != nil {
			t.Fatal(err)
		}
		// Give the Vault its period to take the new token — then revoke the old one, whatever it did.
		for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && !strings.Contains(v8.out.String(), "the token file changed"); {
			time.Sleep(100 * time.Millisecond)
		}
		bao.revoke(t, strings.TrimSpace(string(old)))
		if got, err := fetchSecret(t, v8.baseURL, after); err != nil || got != "secret-sealed-after" {
			t.Fatalf("with the old token revoked: %q, %v", got, err)
		}
		if !strings.Contains(v8.out.String(), "the token file changed") {
			t.Fatalf("the Vault does not say it took the new token:\n%s", v8.out.String())
		}
		if out := v8.out.String(); strings.Contains(out, strings.TrimSpace(string(old))) || strings.Contains(out, strings.TrimSpace(string(fresh))) {
			t.Fatal("a token is in the Vault's log")
		}
	})

	t.Run("the Recorder starts with Transit, after its round trip", func(t *testing.T) {
		rec := startService(t, root, recorderBin, "19747", vaultEnv(withTransit("AUDIT_URL=http://127.0.0.1:1")...)...)
		if !strings.Contains(rec.out.String(), "wrapped by transit:transit/openbastion-vault") {
			t.Fatalf("the Recorder does not say Transit wraps its keys:\n%s", rec.out.String())
		}
		waitUntil(t, 5*time.Second, "the Recorder to renew its token (ADR-0053)", func() bool {
			return strings.Contains(rec.out.String(), "command-recorder: transit: the token is renewed at half its life")
		})
		if !strings.Contains(rec.out.String(), "command-recorder: transit: the token file is read again every") {
			t.Fatalf("the Recorder does not watch its token file (ADR-0056):\n%s", rec.out.String())
		}
	})
}

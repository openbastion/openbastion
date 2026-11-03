// Package integration_test proves the MVP invariant (ADR-0003) across real,
// independently running processes — password-vault and audit-service —
// communicating exactly as documented in
// docs/api/grpc/README.md, over HTTP/JSON instead of
// gRPC (see /NOTES_SANDBOX.md for why).
//
// This test only imports pkg/proxycore (a public module) and the standard
// library — never a service's internal/ packages — because that is
// exactly the boundary the real system enforces: a proxy talks to the
// Vault and the Audit Service over the network, never by reaching into
// their implementation (docs/development/contributing.md).
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// ---------------------------------------------------------------------
// Process harness — builds and runs the real service binaries.
// ---------------------------------------------------------------------

type runningService struct {
	baseURL string
	cmd     *exec.Cmd
	// out is what the process has written to its standard output and error so far.
	out *syncBuffer
}

func repoRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not determine test file location")
	}
	// this file lives at <repoRoot>/test/integration/ssh_flow_test.go
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func buildEnv(root string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		// The module cache is where GOPATH says, which is not always $HOME/go (a
		// container image often sets GOPATH=/go); empty means Go's own default.
		"GOPATH=" + os.Getenv("GOPATH"),
		"GOWORK=" + filepath.Join(root, "go.work"),
		"GOPROXY=off",
		"GOFLAGS=",
		// The flows in this package exercise the services' behaviour, not their
		// transport: they talk to internal endpoints directly, as a developer
		// would. They run in the development mode, stated here rather than left
		// to a default (the default is mutual TLS, ADR-0010). The mutual-TLS mode
		// has its own tests: mtls_flow_test.go.
		"INTERNAL_TLS=disabled",
	}
}

func buildBinary(t *testing.T, root, pkgPath, outName string) string {
	t.Helper()
	outPath := filepath.Join(t.TempDir(), outName)
	cmd := exec.Command("go", "build", "-o", outPath, pkgPath)
	cmd.Dir = root
	cmd.Env = buildEnv(root)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go build %s: %v\n%s", pkgPath, err, out)
	}
	builtFrom.Store(outPath, pkgPath) // what a binary is, whatever its name (audit_sink_test.go)
	return outPath
}

func startService(t *testing.T, root, binPath, port string, extraEnv ...string) *runningService {
	t.Helper()
	cmd := exec.Command(binPath)
	cmd.Env = append(buildEnv(root), append([]string{"PORT=" + port}, withAuditSink(binPath, extraEnv)...)...)
	outBuf := &syncBuffer{}
	cmd.Stdout = outBuf
	cmd.Stderr = outBuf
	if err := cmd.Start(); err != nil {
		t.Fatalf("start %s: %v", binPath, err)
	}

	baseURL := "http://127.0.0.1:" + port
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(baseURL + "/healthz")
		if err != nil {
			lastErr = err
			time.Sleep(50 * time.Millisecond)
			continue
		}
		resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			ready = true
			break
		}
		lastErr = fmt.Errorf("unexpected status %d", resp.StatusCode)
		time.Sleep(50 * time.Millisecond)
	}
	if !ready {
		_ = cmd.Process.Kill()
		t.Fatalf("service at %s did not become healthy: %v\noutput so far:\n%s", baseURL, lastErr, outBuf.String())
	}

	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return &runningService{baseURL: baseURL, cmd: cmd, out: outBuf}
}

// stopService kills a service immediately, before the test's normal
// t.Cleanup would — used to prove persistence survives a process
// actually going away.
func stopService(t *testing.T, svc *runningService) {
	t.Helper()
	_ = svc.cmd.Process.Kill()
	_ = svc.cmd.Wait()
}

// postJSON is a minimal helper for one-off POSTs where the test only
// cares about the status code.
func postJSON(t *testing.T, url string, body any) int {
	t.Helper()
	encoded, err := json.Marshal(body)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	resp, err := http.Post(url, "application/json", bytes.NewReader(encoded))
	if err != nil {
		t.Fatalf("POST %s: %v", url, err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// ---------------------------------------------------------------------
// HTTP adapters satisfying pkg/proxycore's ports — the production
// equivalent of these would be generated gRPC clients (docs/api/grpc/README.md).
// ---------------------------------------------------------------------

type httpVaultClient struct{ baseURL string }

func (c *httpVaultClient) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (proxycore.Fetched, error) {
	body, _ := json.Marshal(map[string]string{
		"scope_token":      scopeToken,
		"calling_proxy_id": callingProxyID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/vault/v1/fetch-credential", bytes.NewReader(body))
	if err != nil {
		return proxycore.Fetched{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return proxycore.Fetched{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: status %d", resp.StatusCode)
	}
	var out struct {
		CredentialType     string `json:"credential_type"`
		CredentialMaterial []byte `json:"credential_material"`
		TargetHost         string `json:"target_host"`
		HostKey            string `json:"host_key"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return proxycore.Fetched{}, err
	}
	return proxycore.Fetched{Type: out.CredentialType, Material: out.CredentialMaterial, TargetHost: out.TargetHost, HostKey: out.HostKey}, nil
}

type httpAuditEmitter struct{ baseURL string }

func (a *httpAuditEmitter) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	body, _ := json.Marshal(map[string]any{
		"actor_id": "", "action": action, "resource_type": resourceType,
		"resource_id": resourceID, "success": success,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

// ---------------------------------------------------------------------
// Test setup helpers — stand in for the Admin UI (onboarding) and the
// Session Broker (AuthorizeScope), both real HTTP calls.
// ---------------------------------------------------------------------

func onboardAccount(t *testing.T, baseURL, id, secret string) {
	t.Helper()
	onboardAccountFull(t, baseURL, id, "integration-test-account", "root", "10.0.0.9", secret, []string{"vault-admin"})
}

func onboardAccountFull(t *testing.T, baseURL, id, name, username, targetHost, secret string, actorRoles []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id": id, "name": name, "username": username, "targetHost": targetHost,
		"protocol": "ssh", "rotationPolicy": "manual",
		"initialSecret": []byte(secret), "actorRoles": actorRoles, "hostKey": targetHostKey,
	})
	resp, err := http.Post(baseURL+"/vault/v1/onboard-account", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("onboard-account: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("onboard-account: status %d", resp.StatusCode)
	}
}

func authorizeScope(t *testing.T, baseURL, sessionID, accountID, proxyServiceID string) string {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "privileged_account_id": accountID,
		"proxy_service_id": proxyServiceID, "ttl_seconds": 60,
	})
	resp, err := http.Post(baseURL+"/vault/v1/authorize-scope", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("authorize-scope: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("authorize-scope: status %d", resp.StatusCode)
	}
	var out struct {
		ScopeToken string `json:"scope_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode authorize-scope response: %v", err)
	}
	return out.ScopeToken
}

// ---------------------------------------------------------------------
// The test.
// ---------------------------------------------------------------------

func TestSSHFlow_EndToEnd_AcrossRealSeparateProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault")
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-ssh-flow")

	authz := startService(t, root, authzBin, "18089")
	vault := startService(t, root, vaultBin, "18081", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL)
	audit := startService(t, root, auditBin, "18082")

	const accountID = "acc_it_ssh"
	const secretValue = "it-test-secret-value"
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "vault-admin", "vault:account-admin:*", "allow")
	onboardAccount(t, vault.baseURL, accountID, secretValue)

	ctx := context.Background()

	t.Run("happy path: authorize, fetch, purge, audit", func(t *testing.T) {
		fetcher := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault.baseURL}, "ssh-proxy")
		terminator := proxycore.NewTerminator(&httpAuditEmitter{baseURL: audit.baseURL})

		scopeToken := authorizeScope(t, vault.baseURL, "session-it-1", accountID, "ssh-proxy")

		cred, err := fetcher.Fetch(ctx, scopeToken)
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if got := string(cred.Material()); got != secretValue {
			t.Fatalf("credential material = %q, want %q", got, secretValue)
		}

		if err := terminator.Terminate(ctx, "session-it-1", cred, true); err != nil {
			t.Fatalf("Terminate: %v", err)
		}
		if !cred.Purged() {
			t.Fatal("credential should be purged after Terminate")
		}

		resp, err := http.Get(audit.baseURL + "/audit/v1/verify-chain")
		if err != nil {
			t.Fatalf("verify-chain: %v", err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("verify-chain: status %d — chain should be intact after a normal flow", resp.StatusCode)
		}
	})

	t.Run("replayed scope token is rejected", func(t *testing.T) {
		fetcher := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault.baseURL}, "ssh-proxy")
		scopeToken := authorizeScope(t, vault.baseURL, "session-it-replay", accountID, "ssh-proxy")

		if _, err := fetcher.Fetch(ctx, scopeToken); err != nil {
			t.Fatalf("first Fetch should succeed: %v", err)
		}
		if _, err := fetcher.Fetch(ctx, scopeToken); err == nil {
			t.Fatal("expected a replayed scope token to be rejected by the Vault")
		}
	})

	t.Run("scope token redeemed by the wrong proxy identity is rejected", func(t *testing.T) {
		scopeToken := authorizeScope(t, vault.baseURL, "session-it-wrong-proxy", accountID, "ssh-proxy")

		// A scope authorized for ssh-proxy must not be redeemable by
		// database-proxy-1 — the least-privilege scoping guarantee
		// underlying ADR-0003 (docs/security/session-security.md).
		wrongProxyFetcher := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vault.baseURL}, "database-proxy-1")
		if _, err := wrongProxyFetcher.Fetch(ctx, scopeToken); err == nil {
			t.Fatal("expected a scope authorized for ssh-proxy to be rejected when redeemed by database-proxy-1")
		}
	})
}

// This file proves the admin surfaces routed through the Gateway in this
// increment — POST /vault/accounts, GET /vault/accounts/{id},
// POST /vault/accounts/{id}/rotate, POST /policies — work across real,
// separate processes: Authentication, Password Vault, Authorization, and
// the API Gateway. Session Broker/ssh-proxy are not needed here since
// this test never creates a session; the Gateway is still started with a
// (deliberately unreachable) Session Broker URL, matching how a real
// deployment might bring services up in any order.
package integration_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

func gatewayOnboardAccount(t *testing.T, baseURL, token, id, name, username, targetHost, initialSecret string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"id": id, "name": name, "username": username, "targetHost": targetHost,
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(initialSecret),
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/vault/accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway onboard-account: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func gatewayGetAccount(t *testing.T, baseURL, token, id string) (map[string]any, int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/vault/accounts/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway get-account: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out, resp.StatusCode
}

func gatewayRotateAccount(t *testing.T, baseURL, token, id string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/vault/accounts/"+id+"/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway rotate-account: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

func gatewayCreatePolicy(t *testing.T, baseURL, token, name, role, resourcePattern, effect, claimedCreatedBy string) int {
	t.Helper()
	body, _ := json.Marshal(map[string]any{
		"name": name, "role": role, "resourcePattern": resourcePattern,
		"effect": effect, "createdBy": claimedCreatedBy,
	})
	req, _ := http.NewRequest(http.MethodPost, baseURL+"/policies", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway create-policy: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// fetchCredentialDirectly plays the role of an already-authorized proxy,
// exactly as ssh-proxy would — used here only to observe whether rotation
// actually changed the stored secret, not to re-prove the proxy flow
// (already covered by ssh_flow_test.go and broker_flow_test.go).
func fetchCredentialDirectly(t *testing.T, vaultBaseURL, accountID string) string {
	t.Helper()
	scopeToken := authorizeScope(t, vaultBaseURL, "admin-routes-it", accountID, "ssh-proxy")
	fetcher := proxycore.NewCredentialFetcher(&httpVaultClient{baseURL: vaultBaseURL}, "ssh-proxy")
	cred, err := fetcher.Fetch(context.Background(), scopeToken)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	material := string(cred.Material())
	cred.Purge()
	return material
}

func TestAdminRoutes_OnboardGetRotatePolicy_ThroughGatewayAcrossRealProcesses(t *testing.T) {
	root := repoRoot(t)

	vaultBin := buildBinary(t, root, "./services/vault/password-vault/cmd/password-vault", "password-vault-5")
	authzBin := buildBinary(t, root, "./services/access/authorization/cmd/authorization", "authorization-4")
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-2")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-2")

	authz := startService(t, root, authzBin, "18302")
	vault := startService(t, root, vaultBin, "18301", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL)
	authn := startService(t, root, authnBin, "18303", "SKIP_DEMO_SEED=1")
	gateway := startService(t, root, gatewayBin, "18304",
		"AUTHENTICATION_URL="+authn.baseURL,
		"SESSION_BROKER_URL=http://127.0.0.1:1", // unused by this test, deliberately unreachable
		"VAULT_URL="+vault.baseURL,
		"AUTHORIZATION_URL="+authz.baseURL,
	)

	authCreateUser(t, authn.baseURL, "admin-operator", "Admin Operator", "admin-pw-123", []string{"admin"})
	token, status := gatewayLogin(t, gateway.baseURL, "admin-operator", "admin-pw-123")
	if status != http.StatusOK {
		t.Fatalf("login: status %d", status)
	}

	const accountID = "acc_admin_routes_it"
	const initialSecret = "admin-routes-initial-secret"

	t.Run("onboarding is denied before any admin policy exists", func(t *testing.T) {
		// The exact gap this increment closes: Password Vault itself
		// refuses the write, not just the Gateway's own auth check
		// (which only requires SOME valid token, not a specific role).
		if status := gatewayOnboardAccount(t, gateway.baseURL, token, accountID, "admin-routes-account", "root", "10.0.0.42:22", initialSecret); status != http.StatusForbidden {
			t.Fatalf("expected 403 before any admin policy exists, got %d", status)
		}
	})

	t.Run("policy creation is denied before any policy-admin grant exists", func(t *testing.T) {
		// The second gap this increment closes: Authorization itself now
		// RBAC-gates its own POST /policies (authz:policy-admin), not
		// just vault writes — proven here the same way, end to end
		// through the real Gateway, before any grant exists at all.
		if status := gatewayCreatePolicy(t, gateway.baseURL, token, "admin-routes-policy", "dba", "vault:account:"+accountID, "allow", "someone-else-entirely"); status != http.StatusForbidden {
			t.Fatalf("expected 403 before any policy-admin grant exists, got %d", status)
		}
	})

	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "admin", "vault:account-admin:*", "allow")
	// The "admin" role used by this test's Gateway operator also needs
	// authz:policy-admin itself — granted here by platform-admin, the
	// bootstrap role — since the later subtest below creates a policy
	// *through the Gateway* as "admin", and Authorization now RBAC-gates
	// that exactly like any other write (authorization_service.go
	// CreatePolicy). Hardcoded literal, not an import of authorization's
	// internal package — same convention as "vault:account-admin:*" above.
	authzCreatePolicy(t, authz.baseURL, []string{"platform-admin"}, "admin", "authz:policy-admin", "allow")

	t.Run("onboard account through the Gateway", func(t *testing.T) {
		if status := gatewayOnboardAccount(t, gateway.baseURL, token, accountID, "admin-routes-account", "root", "10.0.0.42:22", initialSecret); status != http.StatusCreated {
			t.Fatalf("expected 201, got %d", status)
		}
	})

	t.Run("get account metadata through the Gateway — no secret in the response", func(t *testing.T) {
		account, status := gatewayGetAccount(t, gateway.baseURL, token, accountID)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d", status)
		}
		if account["username"] != "root" || account["targetHost"] != "10.0.0.42:22" {
			t.Fatalf("unexpected account metadata: %+v", account)
		}
		for _, secretish := range []string{"encryptedMaterial", "secret", "initialSecret", "password"} {
			if _, present := account[secretish]; present {
				t.Fatalf("account metadata response must never include a %q field", secretish)
			}
		}
	})

	t.Run("rotate through the Gateway actually changes the stored secret", func(t *testing.T) {
		before := fetchCredentialDirectly(t, vault.baseURL, accountID)
		if before != initialSecret {
			t.Fatalf("sanity check failed: expected the initial secret before rotation, got %q", before)
		}

		if status := gatewayRotateAccount(t, gateway.baseURL, token, accountID); status != http.StatusAccepted {
			t.Fatalf("expected 202, got %d", status)
		}

		after := fetchCredentialDirectly(t, vault.baseURL, accountID)
		if after == initialSecret {
			t.Fatal("expected rotation through the Gateway to produce a different, auto-generated secret")
		}
		if after == "" {
			t.Fatal("expected a non-empty auto-generated secret")
		}
	})

	t.Run("policy created through the Gateway actually takes effect", func(t *testing.T) {
		// The client claims a false createdBy — the Gateway overrides it
		// (proven directly, with a fake backend, in api-gateway's own
		// tests). Here we prove the *effect* of the created policy is
		// real: CheckAccess against the real Authorization Service must
		// honor it.
		status := gatewayCreatePolicy(t, gateway.baseURL, token, "admin-routes-policy", "dba", "vault:account:"+accountID, "allow", "someone-else-entirely")
		if status != http.StatusCreated {
			t.Fatalf("expected 201, got %d", status)
		}

		checkBody, _ := json.Marshal(map[string]any{
			"actor_roles": []string{"dba"}, "resource": "vault:account:" + accountID, "action": "session:create",
		})
		resp, err := http.Post(authz.baseURL+"/authz/v1/check-access", "application/json", bytes.NewReader(checkBody))
		if err != nil {
			t.Fatalf("check-access: %v", err)
		}
		defer resp.Body.Close()
		var decision struct {
			Allowed bool `json:"allowed"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&decision)
		if !decision.Allowed {
			t.Fatal("expected the policy created through the Gateway to actually grant access")
		}
	})
}

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
	return gatewayOnboardAccountWith(t, baseURL, token, map[string]any{
		"id": id, "name": name, "username": username, "targetHost": targetHost,
		"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(initialSecret),
	})
}

// gatewayOnboardAccountWith onboards through the Gateway with any body (e.g. a
// reconciliationAccountId, ADR-0037).
func gatewayOnboardAccountWith(t *testing.T, baseURL, token string, fields map[string]any) int {
	t.Helper()
	body, _ := json.Marshal(fields)
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

func gatewayListAccounts(t *testing.T, baseURL, token string) (items []map[string]any, status int) {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, baseURL+"/vault/accounts", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway list-accounts: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode
	}
	var out struct {
		Items []map[string]any `json:"items"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return out.Items, resp.StatusCode
}

func gatewayDeleteAccount(t *testing.T, baseURL, token, id string) int {
	t.Helper()
	req, _ := http.NewRequest(http.MethodDelete, baseURL+"/vault/accounts/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("gateway delete-account: %v", err)
	}
	defer resp.Body.Close()
	return resp.StatusCode
}

// vaultAuthorizeScopeStatus calls Password Vault's AuthorizeScope directly
// (bypassing the Gateway/Session Broker, exactly like fetchCredentialDirectly
// above) and returns the raw status instead of failing the test — used to
// prove a disabled account's scope request is rejected, not to drive a
// successful flow (ssh_flow_test.go's authorizeScope covers that case and
// fatals on anything but 200, which would be the wrong assertion here).
func vaultAuthorizeScopeStatus(t *testing.T, baseURL, sessionID, accountID, proxyServiceID string) int {
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
	// A rotation reaches the target and is audited (ADR-0037).
	auditBin := buildBinary(t, root, "./services/recording-audit/audit-service/cmd/audit-service", "audit-service-admin-routes")
	audit := startService(t, root, auditBin, "18305")
	vault := startService(t, root, vaultBin, "18301", "SKIP_DEMO_SEED=1", "AUTHORIZATION_URL="+authz.baseURL, "AUDIT_URL="+audit.baseURL)
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
	// "admin" changes passwords through sudo (ADR-0037).
	tgt := startRotatableTarget(t, map[string]string{"admin": "admin-routes-rec-pw", "root": initialSecret})

	t.Run("onboarding is denied before any admin policy exists", func(t *testing.T) {
		// The exact gap this increment closes: Password Vault itself
		// refuses the write, not just the Gateway's own auth check
		// (which only requires SOME valid token, not a specific role).
		if status := gatewayOnboardAccount(t, gateway.baseURL, token, accountID, "admin-routes-account", "root", "10.0.0.42:22", initialSecret); status != http.StatusForbidden {
			t.Fatalf("expected 403 before any admin policy exists, got %d", status)
		}
	})

	t.Run("rotation is denied with 403, not 404, before any admin policy exists", func(t *testing.T) {
		// RBAC runs before the existence check, so an unauthorized caller
		// gets the same 403 whether or not the account exists — the 404 that
		// rotate now returns for unknown accounts cannot be used to probe
		// which accounts exist. accountID is not onboarded yet at this point.
		if status := gatewayRotateAccount(t, gateway.baseURL, token, accountID); status != http.StatusForbidden {
			t.Fatalf("expected 403 for an unauthorized rotate on a not-yet-existing account, got %d", status)
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
		if s := vaultOnboard(t, vault.baseURL, map[string]any{"id": accountID + "_rec", "name": "rec", "username": "admin", "targetHost": tgt.addr,
			"protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte("admin-routes-rec-pw"), "actorRoles": []string{"admin"}}); s != http.StatusCreated {
			t.Fatalf("onboard the reconciliation account: %d", s)
		}
		if status := gatewayOnboardAccountWith(t, gateway.baseURL, token, map[string]any{"id": accountID, "name": "admin-routes-account", "username": "root",
			"targetHost": tgt.addr, "protocol": "ssh", "rotationPolicy": "manual", "initialSecret": []byte(initialSecret),
			"reconciliationAccountId": accountID + "_rec"}); status != http.StatusCreated {
			t.Fatalf("expected 201, got %d", status)
		}
	})

	t.Run("get account metadata through the Gateway — no secret in the response", func(t *testing.T) {
		account, status := gatewayGetAccount(t, gateway.baseURL, token, accountID)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d", status)
		}
		if account["username"] != "root" || account["targetHost"] != tgt.addr {
			t.Fatalf("unexpected account metadata: %+v", account)
		}
		// rotationPolicy/createdAt have been part of doc 05's PrivilegedAccount
		// schema since the start but were never actually populated by this
		// HTTP layer until this increment — see NOTES_SANDBOX.md.
		// lastRotatedAt must still be absent: this account has not been
		// rotated yet.
		if account["rotationPolicy"] != "manual" {
			t.Fatalf("expected rotationPolicy %q to be exposed, got %+v", "manual", account)
		}
		if account["createdAt"] == nil || account["createdAt"] == "" {
			t.Fatalf("expected createdAt to be populated, got %+v", account)
		}
		if _, present := account["lastRotatedAt"]; present {
			t.Fatalf("expected lastRotatedAt to be absent before any rotation, got %+v", account)
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

		// The other half of the fix pinned by TestRotate_SetsLastRotatedAt
		// (vault_service_test.go), proven here through a real rotation
		// routed via the real Gateway.
		account, status := gatewayGetAccount(t, gateway.baseURL, token, accountID)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d", status)
		}
		if account["lastRotatedAt"] == nil || account["lastRotatedAt"] == "" {
			t.Fatalf("expected lastRotatedAt to be populated after a rotation, got %+v", account)
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

	t.Run("list through the Gateway includes the onboarded account", func(t *testing.T) {
		items, status := gatewayListAccounts(t, gateway.baseURL, token)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d", status)
		}
		found := false
		for _, item := range items {
			if item["id"] == accountID {
				found = true
			}
		}
		if !found {
			t.Fatalf("expected %q among the listed accounts, got %+v", accountID, items)
		}
	})

	// The list must report the page it SERVED, not the one that was asked
	// for: with no query parameters it serves page 1 of size 20 (doc 05's
	// defaults), and used to say page 0 of size 0.
	t.Run("list reports the page and page size it actually served", func(t *testing.T) {
		for query, want := range map[string][2]int{
			"":                         {1, 20},
			"?page=0&pageSize=0":       {1, 20},
			"?page=3&pageSize=5":       {3, 5},
			"?page=-2&pageSize=100000": {1, 100},
		} {
			req, _ := http.NewRequest(http.MethodGet, gateway.baseURL+"/vault/accounts"+query, nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := http.DefaultClient.Do(req)
			if err != nil {
				t.Fatalf("list %q: %v", query, err)
			}
			var out struct {
				Page     int `json:"page"`
				PageSize int `json:"pageSize"`
			}
			_ = json.NewDecoder(resp.Body).Decode(&out)
			resp.Body.Close()
			if resp.StatusCode != http.StatusOK || out.Page != want[0] || out.PageSize != want[1] {
				t.Fatalf("list %q: status %d, reported page %d / size %d, want %d / %d", query, resp.StatusCode, out.Page, out.PageSize, want[0], want[1])
			}
		}
	})

	// Closes the gap doc 05 §2 documented since this project's inception —
	// GET /vault/accounts and DELETE /vault/accounts/{id} — never
	// implemented until this increment. Soft-delete (DisabledAt), not a
	// hard row delete: see domain.AccountRepository.Disable's doc comment
	// for why (vault_secrets' audit history would be lost to a CASCADE).
	t.Run("disable through the Gateway removes the account from list and get", func(t *testing.T) {
		if status := gatewayDeleteAccount(t, gateway.baseURL, token, accountID); status != http.StatusNoContent {
			t.Fatalf("expected 204, got %d", status)
		}

		if _, status := gatewayGetAccount(t, gateway.baseURL, token, accountID); status != http.StatusNotFound {
			t.Fatalf("expected GET to return 404 for a disabled account, got %d", status)
		}

		items, status := gatewayListAccounts(t, gateway.baseURL, token)
		if status != http.StatusOK {
			t.Fatalf("expected 200, got %d", status)
		}
		for _, item := range items {
			if item["id"] == accountID {
				t.Fatalf("expected the disabled account to be excluded from the list, got %+v", items)
			}
		}
	})

	t.Run("a disabled account can no longer authorize a new credential scope", func(t *testing.T) {
		// Proves AuthorizeScope's own defense-in-depth check (not just
		// GetAccount's 404, which Session Broker's lookup already relies
		// on) — a request that reached this far anyway, bypassing the
		// Gateway/Session Broker entirely, must still be rejected.
		if status := vaultAuthorizeScopeStatus(t, vault.baseURL, "admin-routes-it-post-disable", accountID, "ssh-proxy"); status == http.StatusOK {
			t.Fatal("expected AuthorizeScope to reject a disabled account, got 200")
		}
	})

	t.Run("a disabled account can no longer be rotated", func(t *testing.T) {
		// Rotate checks DisabledAt itself, like AuthorizeScope — before
		// this, rotating a disabled account was accepted (202) and kept
		// creating secret versions on a row the rest of the system treats
		// as deleted. It is refused with 404, the same answer as for an
		// unknown account: the Vault deliberately does not distinguish them.
		if status := gatewayRotateAccount(t, gateway.baseURL, token, accountID); status != http.StatusNotFound {
			t.Fatalf("expected 404 when rotating a disabled account, got %d", status)
		}
	})

	t.Run("rotating an unknown account is reported not found", func(t *testing.T) {
		// Used to be 403 like every other error from this route — see
		// NOTES_SANDBOX.md. An authorized caller now learns the account does
		// not exist instead of being told it was "forbidden".
		if status := gatewayRotateAccount(t, gateway.baseURL, token, "acc_that_was_never_onboarded"); status != http.StatusNotFound {
			t.Fatalf("expected 404 when rotating an unknown account, got %d", status)
		}
	})

	t.Run("re-disabling an already-disabled account is reported not found", func(t *testing.T) {
		// DisableAccount's not-found check runs through GetAccount, which
		// now excludes disabled accounts — matching Rotate's existing
		// not-found semantics for an unknown id (application.VaultService).
		if status := gatewayDeleteAccount(t, gateway.baseURL, token, accountID); status != http.StatusNotFound {
			t.Fatalf("expected 404 when disabling an already-disabled account, got %d", status)
		}
	})
}

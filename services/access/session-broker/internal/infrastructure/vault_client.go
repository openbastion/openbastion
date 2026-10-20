package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// VaultAuthorizationHTTPClient calls ONLY the password-vault's
// /vault/v1/authorize-scope endpoint. It has no method calling
// /vault/v1/fetch-credential — see application.VaultAuthorizer.
type VaultAuthorizationHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

type authorizeScopeRequestBody struct {
	SessionID           string `json:"session_id"`
	PrivilegedAccountID string `json:"privileged_account_id"`
	ProxyServiceID      string `json:"proxy_service_id"`
	TTLSeconds          int    `json:"ttl_seconds"`
}

type authorizeScopeResponseBody struct {
	ScopeToken string    `json:"scope_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (c *VaultAuthorizationHTTPClient) AuthorizeScope(ctx context.Context, sessionID, accountID, proxyServiceID string, ttl time.Duration) (string, time.Time, error) {
	body, _ := json.Marshal(authorizeScopeRequestBody{
		SessionID: sessionID, PrivilegedAccountID: accountID,
		ProxyServiceID: proxyServiceID, TTLSeconds: int(ttl.Seconds()),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/authorize-scope", bytes.NewReader(body))
	if err != nil {
		return "", time.Time{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return "", time.Time{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", time.Time{}, fmt.Errorf("authorize-scope: status %d", resp.StatusCode)
	}
	var out authorizeScopeResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, err
	}
	return out.ScopeToken, out.ExpiresAt, nil
}

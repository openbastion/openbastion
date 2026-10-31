package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
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
		// The Vault says why by a stable code (ADR-0042); its text is not read, and never
		// reaches a client.
		var refusal struct {
			Code string `json:"code"`
		}
		_ = json.NewDecoder(io.LimitReader(resp.Body, 4<<10)).Decode(&refusal)
		if resp.StatusCode == http.StatusConflict && refusal.Code == "no_pinned_host_key" {
			return "", time.Time{}, domain.ErrAccountNotPinned
		}
		return "", time.Time{}, fmt.Errorf("authorize-scope: status %d (%s)", resp.StatusCode, refusal.Code)
	}
	var out authorizeScopeResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", time.Time{}, err
	}
	return out.ScopeToken, out.ExpiresAt, nil
}

// RotateAfterUse tells the Vault that a session on accountID ended (ADR-0037): it rotates the
// secret if the account's policy is post_use.
func (c *VaultAuthorizationHTTPClient) RotateAfterUse(ctx context.Context, accountID, sessionID string) error {
	body, _ := json.Marshal(map[string]string{"accountId": accountID, "sessionId": sessionID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/rotate-after-use", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("rotate-after-use: status %d", resp.StatusCode)
	}
	return nil
}

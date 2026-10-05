package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AccountLookupHTTPClient implements application.AccountLookup by calling
// password-vault's GET /vault/v1/accounts/{id} — metadata only, the
// response has no field that could carry a secret (doc 05 §2).
type AccountLookupHTTPClient struct {
	BaseURL string
}

func (c *AccountLookupHTTPClient) GetAccount(ctx context.Context, accountID string) (targetHost, targetUser string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/vault/v1/accounts/"+accountID, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("get-account: status %d", resp.StatusCode)
	}
	var out struct {
		TargetHost string `json:"targetHost"`
		Username   string `json:"username"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.TargetHost, out.Username, nil
}

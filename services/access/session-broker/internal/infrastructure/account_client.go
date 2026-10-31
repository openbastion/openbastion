package infrastructure

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// AccountLookupHTTPClient implements application.AccountLookup by calling
// password-vault's GET /vault/v1/accounts/{id} — metadata only, the
// response has no field that could carry a secret (doc 05 §2).
type AccountLookupHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *AccountLookupHTTPClient) GetAccount(ctx context.Context, accountID string) (targetHost, targetUser string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/vault/v1/accounts/"+accountID, nil)
	if err != nil {
		return "", "", err
	}
	resp, err := orDefault(c.Client).Do(req)
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

// CheckAccount is application.AccountLookup.CheckAccount: the same read of the account, its
// pinned host key looked at — never the key itself, only whether there is one.
func (c *AccountLookupHTTPClient) CheckAccount(ctx context.Context, accountID string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/vault/v1/accounts/"+url.PathEscape(accountID), nil)
	if err != nil {
		return err
	}
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return domain.ErrAccountNotFound
	default:
		return fmt.Errorf("get-account: status %d", resp.StatusCode)
	}
	var out struct {
		HostKeyFingerprint string `json:"hostKeyFingerprint"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return err
	}
	if out.HostKeyFingerprint == "" {
		return domain.ErrAccountNotPinned
	}
	return nil
}

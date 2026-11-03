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
// response has no field that could carry a secret (docs/api/rest/openapi.yaml).
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
// pinned host key looked at — never the key itself, only whether there is one — and whether
// it requires another person's approval (ADR-0067).
func (c *AccountLookupHTTPClient) CheckAccount(ctx context.Context, accountID string) (approvalRequired bool, accountProtocol string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.BaseURL+"/vault/v1/accounts/"+url.PathEscape(accountID), nil)
	if err != nil {
		return false, "", err
	}
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return false, "", domain.ErrAccountNotFound
	default:
		return false, "", fmt.Errorf("get-account: status %d", resp.StatusCode)
	}
	var out struct {
		Protocol             string `json:"protocol"`
		HostKeyFingerprint   string `json:"hostKeyFingerprint"`
		TLSCertificateSHA256 string `json:"tlsCertificateSha256"`
		TargetDomain         string `json:"targetDomain"`
		ApprovalRequired     bool   `json:"approvalRequired"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&out); err != nil {
		return false, "", err
	}
	switch out.Protocol {
	case "ssh":
		if out.HostKeyFingerprint == "" {
			return false, "", domain.ErrAccountNotPinned
		}
	case "vnc", "rdp":
		if out.TLSCertificateSHA256 == "" || out.TargetDomain == "" {
			return false, "", domain.ErrAccountTLSNotPinned
		}
	default:
		return false, "", domain.ErrUnsupportedProtocol
	}
	return out.ApprovalRequired, out.Protocol, nil
}

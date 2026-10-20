package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// VaultCredentialHTTPClient implements proxycore.VaultClient by calling
// the password-vault's /vault/v1/fetch-credential — the single endpoint
// in the whole system that returns secret material (ADR-0003). Note there
// is no AuthorizeScope method here: ssh-proxy structurally cannot call
// VaultAuthorization, only VaultCredentialIssuance — the mirror image of
// session-broker's VaultAuthorizer, which structurally cannot call
// FetchCredential (see session-broker/internal/application's doc comment).
type VaultCredentialHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *VaultCredentialHTTPClient) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (string, []byte, error) {
	body, _ := json.Marshal(map[string]string{
		"scope_token":      scopeToken,
		"calling_proxy_id": callingProxyID,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/fetch-credential", bytes.NewReader(body))
	if err != nil {
		return "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", nil, fmt.Errorf("fetch-credential: status %d", resp.StatusCode)
	}
	var out struct {
		CredentialType     string `json:"credential_type"`
		CredentialMaterial []byte `json:"credential_material"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", nil, err
	}
	return out.CredentialType, out.CredentialMaterial, nil
}

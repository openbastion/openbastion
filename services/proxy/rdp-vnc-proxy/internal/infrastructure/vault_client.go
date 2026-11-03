package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

// VaultCredentialHTTPClient implements only the credential-issuance port. It
// cannot authorize scopes, and therefore cannot mint its own authority to fetch
// a target credential. In production Client is the mTLS-configured Vault transport.
type VaultCredentialHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *VaultCredentialHTTPClient) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (proxycore.Fetched, error) {
	body, _ := json.Marshal(fetchCredentialRequestBody{ScopeToken: scopeToken, CallingProxyID: callingProxyID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/fetch-credential", bytes.NewReader(body))
	if err != nil {
		return proxycore.Fetched{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return proxycore.Fetched{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: status %d", resp.StatusCode)
	}
	var out fetchCredentialResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return proxycore.Fetched{}, err
	}
	return proxycore.Fetched{Type: out.CredentialType, Material: out.CredentialMaterial, TargetHost: out.TargetHost, HostKey: out.HostKey, TargetUser: out.TargetUser, TLSCertificateSHA256: out.TLSCertificateSHA256, TargetDomain: out.TargetDomain}, nil
}

type fetchCredentialRequestBody struct {
	ScopeToken     string `json:"scope_token"`
	CallingProxyID string `json:"calling_proxy_id"`
}

type fetchCredentialResponseBody struct {
	CredentialType       string `json:"credential_type"`
	CredentialMaterial   []byte `json:"credential_material"`
	TargetHost           string `json:"target_host"`
	HostKey              string `json:"host_key"`
	TargetUser           string `json:"target_user"`
	TLSCertificateSHA256 string `json:"tls_certificate_sha256"`
	TargetDomain         string `json:"target_domain"`
}

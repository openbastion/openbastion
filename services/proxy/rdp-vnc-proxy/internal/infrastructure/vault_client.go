package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/pkg/securemem"
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
	defer securemem.Zero(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/fetch-credential", bytes.NewReader(body))
	if err != nil {
		return proxycore.Fetched{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	req.Header.Set("Pragma", "no-cache")
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
	const maxCredentialResponse = 1 << 20
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialResponse+1))
	defer securemem.Zero(responseBody)
	if err != nil {
		return proxycore.Fetched{}, err
	}
	if len(responseBody) > maxCredentialResponse {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: response exceeds limit")
	}
	var out fetchCredentialResponseBody
	if err := json.Unmarshal(responseBody, &out); err != nil {
		securemem.Zero(out.CredentialMaterial)
		return proxycore.Fetched{}, err
	}
	if len(out.CredentialMaterial) == 0 {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: empty credential material")
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

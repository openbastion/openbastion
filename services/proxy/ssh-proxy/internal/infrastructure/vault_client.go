package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/openbastion/openbastion/pkg/proxycore"
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

func (c *VaultCredentialHTTPClient) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (proxycore.Fetched, error) {
	requestBody, _ := json.Marshal(fetchCredentialRequestBody{ScopeToken: scopeToken, CallingProxyID: callingProxyID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/vault/v1/fetch-credential", bytes.NewReader(requestBody))
	if err != nil {
		return proxycore.Fetched{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return proxycore.Fetched{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: status %d", resp.StatusCode)
	}
	const maxCredentialResponse = 1 << 20
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, maxCredentialResponse+1))
	defer zeroCredentialBytes(responseBody)
	if err != nil {
		return proxycore.Fetched{}, err
	}
	if len(responseBody) > maxCredentialResponse {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: response exceeds limit")
	}
	var out fetchCredentialResponseBody
	if err := json.Unmarshal(responseBody, &out); err != nil {
		zeroCredentialBytes(out.CredentialMaterial)
		return proxycore.Fetched{}, err
	}
	if len(out.CredentialMaterial) == 0 {
		return proxycore.Fetched{}, fmt.Errorf("fetch-credential: empty credential material")
	}
	return proxycore.Fetched{Type: out.CredentialType, Material: out.CredentialMaterial, TargetHost: out.TargetHost, HostKey: out.HostKey, TargetUser: out.TargetUser, TLSCertificateSHA256: out.TLSCertificateSHA256, TargetDomain: out.TargetDomain}, nil
}

// The bodies of the Vault's fetch-credential, with the field names of VaultCredentialIssuance's
// messages (test/integration/contract_test.go holds them to it, ADR-0050).
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

func zeroCredentialBytes(value []byte) {
	for i := range value {
		value[i] = 0
	}
}

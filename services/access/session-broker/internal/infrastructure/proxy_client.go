package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// ProxyClientHTTPClient implements application.ProxyClient by calling a
// proxy's /internal/v1/establish-session — the HTTP stand-in for
// ProxyControl.EstablishSession (proto/proxy/v1/proxy_control.proto,
// doc 07 §4). MVP has exactly one proxy family (SSH), so one BaseURL is
// enough; a registry keyed by proxyServiceID is a v1.0 concern.
type ProxyClientHTTPClient struct {
	BaseURL string
}

func (c *ProxyClientHTTPClient) EstablishSession(ctx context.Context, sessionID, targetHost, targetUser, scopeToken string, ttl time.Duration) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "target_host": targetHost, "target_user": targetUser,
		"vault_scope_token": scopeToken, "ttl_seconds": int(ttl.Seconds()),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/v1/establish-session", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("establish-session: status %d", resp.StatusCode)
	}
	var out struct {
		ProxyEndpoint    string `json:"proxy_endpoint"`
		ConnectionTicket string `json:"connection_ticket"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.ProxyEndpoint, out.ConnectionTicket, nil
}

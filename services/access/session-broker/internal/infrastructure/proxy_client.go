package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// ProxyClientHTTPClient implements application.ProxyClient by calling a
// proxy's /internal/v1/establish-session — the HTTP stand-in for
// ProxyControl.EstablishSession (proto/proxy/v1/proxy_control.proto,
// doc 07 §4). MVP has exactly one proxy family (SSH), so one BaseURL is
// enough; a registry keyed by proxyServiceID is a v1.0 concern.
type ProxyClientHTTPClient struct {
	BaseURL string
}

func (c *ProxyClientHTTPClient) EstablishSession(ctx context.Context, sessionID, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool) (string, string, error) {
	body, _ := json.Marshal(map[string]any{
		"session_id": sessionID, "target_host": targetHost, "target_user": targetUser,
		"vault_scope_token": scopeToken, "ttl_seconds": int(ttl.Seconds()),
		"break_glass": breakGlass,
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
		// The proxy answers 503 "recording unavailable" when its recording
		// policy refuses the session (ADR-0008). Key on the body as well as the
		// status: a bare 503 (a load balancer with no backend, say) is not that.
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
		if resp.StatusCode == http.StatusServiceUnavailable && strings.HasPrefix(string(body), "recording unavailable") {
			return "", "", fmt.Errorf("%w: establish-session refused by the proxy", domain.ErrRecordingUnavailable)
		}
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

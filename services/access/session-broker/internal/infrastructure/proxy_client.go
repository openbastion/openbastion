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
// docs/api/grpc/README.md §4). MVP has exactly one proxy family (SSH), so one BaseURL is
// enough; a registry keyed by proxyServiceID is a v0.0.1 concern.
type ProxyClientHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *ProxyClientHTTPClient) EstablishSession(ctx context.Context, sessionID, protocol, targetHost, targetUser, scopeToken string, ttl time.Duration, breakGlass bool, clipboard domain.ClipboardRights) (string, string, error) {
	body, _ := json.Marshal(establishSessionRequestBody{
		SessionID: sessionID, Protocol: protocol, TargetHost: targetHost, TargetUser: targetUser,
		VaultScopeToken: scopeToken, TTLSeconds: int(ttl.Seconds()), BreakGlass: breakGlass,
		ClipboardToTarget: clipboard.ToTarget, ClipboardFromTarget: clipboard.FromTarget,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/v1/establish-session", bytes.NewReader(body))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
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
	var out establishSessionResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", err
	}
	return out.ProxyEndpoint, out.ConnectionTicket, nil
}

// RevokeSession implements application.ProxyClient by calling the proxy's
// /internal/v1/revoke-session (ADR-0018). Only a 200 is a revocation: the proxy
// answers 200 once the session's connections are closed, and nothing else when
// they are not (or when it does not know the route, as an older proxy would), so
// the Broker never calls a session ended that may still be open.
func (c *ProxyClientHTTPClient) RevokeSession(ctx context.Context, sessionID string, remaining time.Duration) error {
	seconds := int(remaining.Seconds()) + 1 // rounded up: never a memory shorter than asked
	if seconds < 1 {
		seconds = 1
	}
	body, _ := json.Marshal(revokeSessionRequestBody{SessionID: sessionID, TTLSeconds: seconds})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/internal/v1/revoke-session", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<16))
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("revoke-session: status %d", resp.StatusCode)
	}
	return nil
}

// The bodies of the proxy's internal routes, with the field names of ProxyControl's messages
// (test/integration/contract_test.go holds them to it, ADR-0050).
type establishSessionRequestBody struct {
	SessionID       string `json:"session_id"`
	Protocol        string `json:"protocol"`
	TargetHost      string `json:"target_host"`
	TargetUser      string `json:"target_user"`
	VaultScopeToken string `json:"vault_scope_token"`
	TTLSeconds      int    `json:"ttl_seconds"`
	BreakGlass      bool   `json:"break_glass"`
	// The clipboard's rights of an RDP session (ADR-0096), as the Broker granted them.
	ClipboardToTarget   bool `json:"clipboard_to_target"`
	ClipboardFromTarget bool `json:"clipboard_from_target"`
}

type establishSessionResponseBody struct {
	ProxyEndpoint    string `json:"proxy_endpoint"`
	ConnectionTicket string `json:"connection_ticket"`
}

type revokeSessionRequestBody struct {
	SessionID  string `json:"session_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

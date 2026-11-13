package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

type AuditHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

type auditEventRequest struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
	// Details are bounded metadata, covered by the chain's hash (ADR-0068): never a secret, never
	// a clipboard text.
	Details map[string]string `json:"details,omitempty"`
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	return c.emit(ctx, auditEventRequest{Action: action, ResourceType: resourceType, ResourceID: resourceID, Success: success})
}

// EmitClipboard writes session.clipboard (ADR-0096 §5): the direction, the size and the hash of
// the text, and why a refused transfer was, never the text.
func (c *AuditHTTPClient) EmitClipboard(ctx context.Context, sessionID string, event proxycore.ClipboardEvent) error {
	return c.emit(ctx, auditEventRequest{Action: "session.clipboard", ResourceType: "session", ResourceID: sessionID,
		Success: event.Success, Details: proxycore.ClipboardDetails(event)})
}

var _ proxycore.ClipboardAuditor = (*AuditHTTPClient)(nil)

func (c *AuditHTTPClient) emit(ctx context.Context, event auditEventRequest) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	client := c.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

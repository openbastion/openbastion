package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuditHTTPClient writes an event to the Audit Service — the same call, and the
// same request shape, as the Session Broker's client. It is how a read of a
// recording is on the record before it is served (ADR-0022).
type AuditHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

type emitEventRequestBody struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
}

// EmitEvent succeeds only on a 200: anything else is an event that may not be in
// the trail, and the caller must not act as if it were.
func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	body, _ := json.Marshal(emitEventRequestBody{
		ActorID: actorID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Success: success,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

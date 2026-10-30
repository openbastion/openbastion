package infrastructure

// The Vault's client of the Audit Service (ADR-0037): its rotations are written to the trail.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type AuditHTTPClient struct {
	BaseURL string
	// Client is the mutual-TLS client pinned to the Audit Service under INTERNAL_TLS
	// (ADR-0010); nil means http.DefaultClient.
	Client *http.Client
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	body, _ := json.Marshal(map[string]any{"actor_id": actorID, "action": action, "resource_type": resourceType,
		"resource_id": resourceID, "success": success})
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

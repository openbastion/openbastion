package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type AuditHTTPClient struct {
	BaseURL string
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	body, _ := json.Marshal(map[string]any{
		"actor_id": "", "action": action, "resource_type": resourceType,
		"resource_id": resourceID, "success": success,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

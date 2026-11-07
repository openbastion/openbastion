package infrastructure

// The Authentication Service's client of the Audit Service (ADR-0064): logins and the second
// factor's administrative gestures are written to the chain, under this service's certificate.

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// AuditTimeout bounds one write: a login waits for it (no audit, no token).
const AuditTimeout = 5 * time.Second

type AuditHTTPClient struct {
	BaseURL string
	// Client is the mutual-TLS client pinned to the Audit Service under INTERNAL_TLS (ADR-0010);
	// nil means http.DefaultClient.
	Client *http.Client
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	return c.EmitEventWithDetails(ctx, actorID, action, resourceType, resourceID, nil, success)
}

// EmitEventWithDetails writes an event with bounded details, covered by the chain's hash (ADR-0068).
func (c *AuditHTTPClient) EmitEventWithDetails(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error {
	ctx, cancel := context.WithTimeout(ctx, AuditTimeout)
	defer cancel()
	body, _ := json.Marshal(emitEventRequestBody{ActorID: actorID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Details: details, Success: success})
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

// The body of the Audit Service's emit-event, with the field names of AuditIngestion's message
// (test/integration/contract_test.go holds them to it, ADR-0050).
type emitEventRequestBody struct {
	ActorID      string            `json:"actor_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	Success      bool              `json:"success"`
}

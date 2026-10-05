package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type AuthorizationHTTPClient struct {
	BaseURL string
}

func (c *AuthorizationHTTPClient) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	body, _ := json.Marshal(map[string]any{"actor_roles": actorRoles, "resource": resource, "action": action})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authz/v1/check-access", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("check-access: status %d", resp.StatusCode)
	}
	var out struct {
		Allowed        bool   `json:"allowed"`
		DecisionReason string `json:"decision_reason"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", err
	}
	return out.Allowed, out.DecisionReason, nil
}

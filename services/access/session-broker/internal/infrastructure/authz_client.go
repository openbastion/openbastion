// Package infrastructure implements the Session Broker's outbound HTTP
// clients (to Authorization, VaultAuthorization, AuditIngestion) and its
// in-memory session store. Each client satisfies exactly one narrow port
// defined in internal/application — see application.VaultAuthorizer's
// doc comment in particular for why that one has no FetchCredential
// method at all.
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

type checkAccessRequestBody struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type checkAccessResponseBody struct {
	Allowed        bool   `json:"allowed"`
	DecisionReason string `json:"decision_reason"`
}

func (c *AuthorizationHTTPClient) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	body, _ := json.Marshal(checkAccessRequestBody{ActorRoles: actorRoles, Resource: resource, Action: action})
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
	var out checkAccessResponseBody
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return false, "", err
	}
	return out.Allowed, out.DecisionReason, nil
}

package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthorizationHTTPClient asks the Authorization Service whether a set of
// roles may perform an action on a resource — the same call, and the same
// request shape, as the Password Vault's client.
type AuthorizationHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *AuthorizationHTTPClient) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	body, _ := json.Marshal(checkAccessRequestBody{ActorRoles: actorRoles, Resource: resource, Action: action})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authz/v1/check-access", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
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

// The bodies of the Authorization Service's check-access (docs/api/grpc/README.md §8; not yet in
// proto/, declared as such in test/integration/contract_test.go).
type checkAccessRequestBody struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type checkAccessResponseBody struct {
	Allowed        bool   `json:"allowed"`
	DecisionReason string `json:"decision_reason"`
}

package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"

	"github.com/openbastion/openbastion/services/access/workflow-service/internal/domain"
)

type UserDirectoryHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

type userAuthorizationContextResponse struct {
	UserID string   `json:"user_id"`
	Exists bool     `json:"exists"`
	Active bool     `json:"active"`
	Roles  []string `json:"roles"`
}

func (c *UserDirectoryHTTPClient) GetAuthorizationContext(ctx context.Context, userID string) (domain.UserAuthorizationContext, error) {
	endpoint := c.BaseURL + "/auth/v1/internal/users/" + url.PathEscape(userID) + "/authorization-context"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return domain.UserAuthorizationContext{}, err
	}
	resp, err := doInternalRequest(c.client(), req)
	if err != nil {
		return domain.UserAuthorizationContext{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return domain.UserAuthorizationContext{}, fmt.Errorf("user directory: status %d", resp.StatusCode)
	}
	var out userAuthorizationContextResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil || out.UserID != userID || out.Roles == nil || (!out.Exists && (out.Active || len(out.Roles) != 0)) || (!out.Active && len(out.Roles) != 0) {
		return domain.UserAuthorizationContext{}, fmt.Errorf("user directory: invalid authorization context")
	}
	return domain.UserAuthorizationContext{UserID: out.UserID, Exists: out.Exists, Active: out.Active, Roles: append([]string{}, out.Roles...)}, nil
}

type authorizationCheckAccessRequest struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type authorizationCheckAccessResponse struct {
	Allowed          bool   `json:"allowed"`
	RequiresApproval bool   `json:"requires_approval"`
	Reason           string `json:"decision_reason"`
}

type auditEmitEventRequest struct {
	ActorID      string            `json:"actor_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	Success      bool              `json:"success"`
}

type AuthorizationHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *AuthorizationHTTPClient) CheckAccess(ctx context.Context, _ string, actorRoles []string, resource, action string) (bool, string, error) {
	body, err := json.Marshal(authorizationCheckAccessRequest{ActorRoles: actorRoles, Resource: resource, Action: action})
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/authz/v1/check-access", bytes.NewReader(body))
	if err != nil {
		return false, "", err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := doInternalRequest(c.client(), req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("authorization: status %d", resp.StatusCode)
	}
	var out authorizationCheckAccessResponse
	dec := json.NewDecoder(io.LimitReader(resp.Body, 8<<10))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&out); err != nil {
		return false, "", err
	}
	return out.Allowed, out.Reason, nil
}

type AuditHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error {
	body, err := json.Marshal(auditEmitEventRequest{ActorID: actorID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Details: details, Success: success})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := doInternalRequest(c.client(), req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("audit: status %d", resp.StatusCode)
	}
	return nil
}

func (c *UserDirectoryHTTPClient) client() *http.Client { return orDefault(c.Client) }
func (c *AuthorizationHTTPClient) client() *http.Client { return orDefault(c.Client) }
func (c *AuditHTTPClient) client() *http.Client         { return orDefault(c.Client) }

func doInternalRequest(client *http.Client, req *http.Request) (*http.Response, error) {
	bounded := *orDefault(client)
	bounded.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	if bounded.Timeout == 0 {
		bounded.Timeout = 5 * time.Second
	}
	return bounded.Do(req)
}

func orDefault(client *http.Client) *http.Client {
	if client != nil {
		return client
	}
	return http.DefaultClient
}

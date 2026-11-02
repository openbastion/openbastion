package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
)

type AuthorizationHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *AuthorizationHTTPClient) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	body, err := json.Marshal(struct {
		ActorRoles []string `json:"actor_roles"`
		Resource   string   `json:"resource"`
		Action     string   `json:"action"`
	}{ActorRoles: actorRoles, Resource: resource, Action: action})
	if err != nil {
		return false, "", fmt.Errorf("encoding authorization request: %w", err)
	}
	endpoint, err := serviceEndpoint(c.BaseURL, "/authz/v1/check-access")
	if err != nil {
		return false, "", err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return false, "", fmt.Errorf("building authorization request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Client == nil {
		return false, "", fmt.Errorf("authorization HTTP client is missing")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return false, "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false, "", fmt.Errorf("check-access: status %d", resp.StatusCode)
	}
	var result struct {
		Allowed          bool   `json:"allowed"`
		RequiresApproval bool   `json:"requires_approval"`
		DecisionReason   string `json:"decision_reason"`
	}
	if err := decodeResponse(resp.Body, &result); err != nil {
		return false, "", fmt.Errorf("decoding authorization response: %w", err)
	}
	return result.Allowed && !result.RequiresApproval, result.DecisionReason, nil
}

type AuditHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	body, err := json.Marshal(struct {
		ActorID      string `json:"actor_id"`
		Action       string `json:"action"`
		ResourceType string `json:"resource_type"`
		ResourceID   string `json:"resource_id"`
		Success      bool   `json:"success"`
	}{ActorID: actorID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Success: success})
	if err != nil {
		return fmt.Errorf("encoding audit event: %w", err)
	}
	endpoint, err := serviceEndpoint(c.BaseURL, "/audit/v1/emit-event")
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("building audit request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Client == nil {
		return fmt.Errorf("audit HTTP client is missing")
	}
	resp, err := c.Client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	var result struct {
		EventID string `json:"event_id"`
	}
	if err := decodeResponse(resp.Body, &result); err != nil {
		return fmt.Errorf("decoding audit response: %w", err)
	}
	if result.EventID == "" {
		return fmt.Errorf("audit service returned an empty event id")
	}
	return nil
}

func serviceEndpoint(baseURL, route string) (string, error) {
	u, err := url.Parse(baseURL)
	if err != nil || u.Host == "" || u.User != nil || u.Opaque != "" ||
		(u.Scheme != "https" && u.Scheme != "http") || (u.Path != "" && u.Path != "/") ||
		u.RawQuery != "" || u.Fragment != "" {
		return "", fmt.Errorf("service URL must be an HTTP(S) origin")
	}
	u.Path = route
	return u.String(), nil
}

func decodeResponse(body io.Reader, dst any) error {
	const maxResponseBytes = 16 << 10
	data, err := io.ReadAll(io.LimitReader(body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(data) > maxResponseBytes {
		return fmt.Errorf("service response exceeds %d bytes", maxResponseBytes)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return fmt.Errorf("service response contains trailing data")
	}
	return nil
}

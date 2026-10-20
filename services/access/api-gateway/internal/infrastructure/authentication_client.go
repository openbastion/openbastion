package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

// AuthenticationHTTPClient implements application.TokenVerifier by
// calling the Authentication Service's /auth/v1/verify.
type AuthenticationHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *AuthenticationHTTPClient) VerifyToken(ctx context.Context, token string) (userID, username string, roles []string, err error) {
	body, _ := json.Marshal(map[string]string{"token": token})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/auth/v1/verify", bytes.NewReader(body))
	if err != nil {
		return "", "", nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return "", "", nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", "", nil, fmt.Errorf("verify: status %d", resp.StatusCode)
	}
	var out struct {
		UserID   string   `json:"userId"`
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", "", nil, err
	}
	return out.UserID, out.Username, out.Roles, nil
}

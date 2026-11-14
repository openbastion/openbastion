package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
)

const (
	mfaActionStartPath   = "/auth/v1/internal/action-step-up/start"
	mfaActionVerifyPath  = "/auth/v1/internal/action-step-up/verify"
	mfaActionConsumePath = "/auth/v1/internal/action-step-up/consume"
	maxMFAActionBody     = 1 << 20
)

type MFAActionBinding = application.MFAActionBinding
type MFAActionStart = application.MFAActionStart
type MFAActionProof = application.MFAActionProof
type MFAActionGrant = application.MFAActionGrant

type mfaActionRequestContext struct {
	ActorUserID string `json:"actor_user_id"`
}

// MFAActionClient calls Authentication over a client pinned to mtls.Authentication.
type MFAActionClient struct {
	BaseURL string
	Client  *http.Client
}

func (c *MFAActionClient) Start(ctx context.Context, b application.MFAActionBinding) (application.MFAActionStart, error) {
	var out application.MFAActionStart
	payload := mfaActionStartRequestBody{Context: mfaActionRequestContext{b.ActorUserID}, SessionID: b.SessionID, AccountID: b.AccountID, Protocol: b.Protocol, Action: b.Action}
	if err := c.post(ctx, mfaActionStartPath, payload, &out); err != nil {
		return application.MFAActionStart{}, err
	}
	if out.Challenge == "" || out.ExpiresIn <= 0 || len(out.Factors) == 0 {
		return application.MFAActionStart{}, fmt.Errorf("authentication action-step-up start: invalid response")
	}
	return out, nil
}

func (c *MFAActionClient) Verify(ctx context.Context, b application.MFAActionBinding, p application.MFAActionProof) (application.MFAActionGrant, error) {
	var out application.MFAActionGrant
	payload := mfaActionVerifyRequestBody{Context: mfaActionRequestContext{b.ActorUserID}, SessionID: b.SessionID, AccountID: b.AccountID, Protocol: b.Protocol, Action: b.Action, Challenge: p.Challenge, Factor: p.Factor, TOTPCode: p.TOTPCode, WebAuthnResponse: p.WebAuthnResponse}
	if err := c.post(ctx, mfaActionVerifyPath, payload, &out); err != nil {
		return application.MFAActionGrant{}, err
	}
	if out.Grant == "" || out.ExpiresIn <= 0 {
		return application.MFAActionGrant{}, fmt.Errorf("authentication action-step-up verify: invalid response")
	}
	return out, nil
}

func (c *MFAActionClient) Consume(ctx context.Context, b application.MFAActionBinding, grant string) error {
	if strings.TrimSpace(grant) == "" {
		return fmt.Errorf("authentication action-step-up consume: empty grant")
	}
	var out mfaActionConsumeResponseBody
	payload := mfaActionConsumeRequestBody{Context: mfaActionRequestContext{b.ActorUserID}, SessionID: b.SessionID, AccountID: b.AccountID, Protocol: b.Protocol, Action: b.Action, Grant: grant}
	if err := c.post(ctx, mfaActionConsumePath, payload, &out); err != nil {
		return err
	}
	if !out.Consumed {
		return fmt.Errorf("authentication action-step-up consume: grant was not consumed")
	}
	return nil
}

func (c *MFAActionClient) post(ctx context.Context, path string, payload, result any) error {
	if c == nil || c.BaseURL == "" {
		return fmt.Errorf("authentication action-step-up: client is not configured")
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("authentication action-step-up: encode request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(c.BaseURL, "/")+path, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("authentication action-step-up: create request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Cache-Control", "no-store")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return fmt.Errorf("authentication action-step-up: request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication action-step-up: upstream status %d", resp.StatusCode)
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxMFAActionBody))
	if err := dec.Decode(result); err != nil {
		return fmt.Errorf("authentication action-step-up: invalid response: %w", err)
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		return fmt.Errorf("authentication action-step-up: invalid trailing response data")
	}
	return nil
}

// These DTOs mirror action_step_up.proto. Keeping them named lets the contract test
// detect field drift between HTTP/JSON and the protobuf source contract.
type mfaActionStartRequestBody struct {
	Context   mfaActionRequestContext `json:"context"`
	SessionID string                  `json:"session_id"`
	AccountID string                  `json:"account_id"`
	Protocol  string                  `json:"protocol"`
	Action    string                  `json:"action"`
}

type mfaActionVerifyRequestBody struct {
	Context          mfaActionRequestContext `json:"context"`
	SessionID        string                  `json:"session_id"`
	AccountID        string                  `json:"account_id"`
	Protocol         string                  `json:"protocol"`
	Action           string                  `json:"action"`
	Challenge        string                  `json:"challenge"`
	Factor           string                  `json:"factor"`
	TOTPCode         string                  `json:"totp_code,omitempty"`
	WebAuthnResponse json.RawMessage         `json:"webauthn_response,omitempty"`
}

type mfaActionConsumeRequestBody struct {
	Context   mfaActionRequestContext `json:"context"`
	SessionID string                  `json:"session_id"`
	AccountID string                  `json:"account_id"`
	Protocol  string                  `json:"protocol"`
	Action    string                  `json:"action"`
	Grant     string                  `json:"grant"`
}

type mfaActionConsumeResponseBody struct {
	Consumed bool `json:"consumed"`
}

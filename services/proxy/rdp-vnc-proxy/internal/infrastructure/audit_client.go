package infrastructure

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/openbastion/openbastion/pkg/proxycore"
)

type AuditHTTPClient struct {
	BaseURL string
	Client  *http.Client
}

type auditEventRequest struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
	// Details are bounded metadata, covered by the chain's hash (ADR-0068): never a secret, never
	// a clipboard text.
	Details map[string]string `json:"details,omitempty"`
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	return c.emit(ctx, auditEventRequest{Action: action, ResourceType: resourceType, ResourceID: resourceID, Success: success})
}

// EmitClipboard writes session.clipboard (ADR-0096 §5): the direction, the size and the hash of
// the text, and why a refused transfer was, never the text.
func (c *AuditHTTPClient) EmitClipboard(ctx context.Context, sessionID string, event proxycore.ClipboardEvent) error {
	return c.emit(ctx, auditEventRequest{Action: "session.clipboard", ResourceType: "session", ResourceID: sessionID,
		Success: event.Success, Details: proxycore.ClipboardDetails(event)})
}

// AuditSecretInput stores only the protocol and account reference, and for an operator's password
// its size and salted fingerprint (ADR-0133 §4); secret bytes never enter the audit request.
func (c *AuditHTTPClient) AuditSecretInput(ctx context.Context, evidence proxycore.SecretInputEvidence) error {
	details, ok := secretInputDetails(evidence)
	if !ok {
		return proxycore.ErrSecretInjectionInvalid
	}
	action := "session.secret_injection_started"
	if evidence.Source == proxycore.SecretInputOperator {
		action = "session.secret_paste_started"
	}
	return c.emit(ctx, auditEventRequest{Action: action, ResourceType: "session", ResourceID: evidence.SessionID, Success: true, Details: details})
}

// AuditSecretInputResult records whether the proxy's target-input attempt completed.
func (c *AuditHTTPClient) AuditSecretInputResult(ctx context.Context, evidence proxycore.SecretInputEvidence, success bool) error {
	details, ok := secretInputDetails(evidence)
	if !ok {
		return proxycore.ErrSecretInjectionInvalid
	}
	action := map[bool]string{true: "session.secret_injected", false: "session.secret_injection_failed"}[success]
	if evidence.Source == proxycore.SecretInputOperator {
		action = map[bool]string{true: "session.secret_pasted", false: "session.secret_paste_failed"}[success]
	}
	return c.emit(ctx, auditEventRequest{Action: action, ResourceType: "session", ResourceID: evidence.SessionID, Success: success, Details: details})
}

// secretInputDetails: a Vault secret's account reference; an operator's password's account, size,
// salted fingerprint and salt (the names the SSH proxy writes), never the text.
func secretInputDetails(evidence proxycore.SecretInputEvidence) (map[string]string, bool) {
	if evidence.AccountID == "" || len(evidence.InjectionID) != 32 || (evidence.Protocol != "vnc" && evidence.Protocol != "rdp") {
		return nil, false
	}
	details := map[string]string{"protocol": evidence.Protocol, "account_id": evidence.AccountID, "injection_id": evidence.InjectionID}
	switch evidence.Source {
	case proxycore.SecretInputVault:
		if evidence.Length != 0 || evidence.SHA256 != "" || evidence.Salt != "" {
			return nil, false
		}
	case proxycore.SecretInputOperator:
		if evidence.Length < 1 || len(evidence.SHA256) != 64 || len(evidence.Salt) != 32 {
			return nil, false
		}
		details["bytes"], details["sha256"], details["salt"] = strconv.Itoa(evidence.Length), evidence.SHA256, evidence.Salt
	default:
		return nil, false
	}
	return details, true
}

// AuditPasteRefused records a paste the proxy did not type (ADR-0133): the reason, never the text.
func (c *AuditHTTPClient) AuditPasteRefused(ctx context.Context, sessionID, protocol, reason string) error {
	if protocol != "vnc" && protocol != "rdp" {
		return proxycore.ErrSecretInjectionInvalid
	}
	return c.emit(ctx, auditEventRequest{Action: "session.secret_paste_refused", ResourceType: "session", ResourceID: sessionID,
		Success: false, Details: map[string]string{"protocol": protocol, "reason": reason}})
}

var _ proxycore.PasteRefusalAuditor = (*AuditHTTPClient)(nil)
var _ proxycore.ClipboardAuditor = (*AuditHTTPClient)(nil)
var _ proxycore.SecretInputAuditor = (*AuditHTTPClient)(nil)

func (c *AuditHTTPClient) emit(ctx context.Context, event auditEventRequest) error {
	body, err := json.Marshal(event)
	if err != nil {
		return err
	}
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

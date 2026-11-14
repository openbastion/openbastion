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

const (
	auditDetailProtocol  = "protocol"
	auditDetailAccountID = "account_id"
	auditDetailBytes     = "bytes"
	auditDetailSHA256    = "sha256"
)

type AuditHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, action, resourceType, resourceID string, success bool) error {
	body, _ := json.Marshal(emitEventRequestBody{Action: action, ResourceType: resourceType, ResourceID: resourceID, Success: success})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
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

// AuditSecretInput writes only the safe evidence required by ADR-0097. The
// secret bytes are not accepted by this method or serialized into the event.
func (c *AuditHTTPClient) AuditSecretInput(ctx context.Context, evidence proxycore.SecretInputEvidence) error {
	action := "session.secret_injection_started"
	details := map[string]string{auditDetailProtocol: evidence.Protocol, auditDetailAccountID: evidence.AccountID}
	if evidence.Source == proxycore.SecretInputOperator {
		action = "session.secret_paste_started"
		details[auditDetailBytes] = strconv.Itoa(evidence.Length)
		details[auditDetailSHA256] = evidence.SHA256
	} else if evidence.Source != proxycore.SecretInputVault {
		return proxycore.ErrSecretInjectionInvalid
	}
	body, err := json.Marshal(emitEventRequestBody{Action: action, ResourceType: "session", ResourceID: evidence.SessionID, Details: details, Success: true})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

// AuditSecretInputResult records the outcome after target typing. The pre-event
// remains durable even if this second audit write fails, making the operation
// distinguishable from an injection that was never attempted.
func (c *AuditHTTPClient) AuditSecretInputResult(ctx context.Context, evidence proxycore.SecretInputEvidence, success bool) error {
	action := "session.secret_injected"
	if !success {
		action = "session.secret_injection_failed"
	}
	details := map[string]string{auditDetailProtocol: evidence.Protocol, auditDetailAccountID: evidence.AccountID}
	if evidence.Source == proxycore.SecretInputOperator {
		action = "session.secret_pasted"
		if !success {
			action = "session.secret_paste_failed"
		}
		details[auditDetailBytes] = strconv.Itoa(evidence.Length)
		details[auditDetailSHA256] = evidence.SHA256
	} else if evidence.Source != proxycore.SecretInputVault {
		return proxycore.ErrSecretInjectionInvalid
	}
	body, err := json.Marshal(emitEventRequestBody{Action: action, ResourceType: "session", ResourceID: evidence.SessionID, Details: details, Success: success})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/emit-event", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("emit-event: status %d", resp.StatusCode)
	}
	return nil
}

var _ proxycore.SecretInputAuditor = (*AuditHTTPClient)(nil)

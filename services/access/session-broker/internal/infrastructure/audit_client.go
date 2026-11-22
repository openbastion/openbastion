package infrastructure

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type AuditHTTPClient struct {
	BaseURL string

	// Client is the HTTP client to use; nil means http.DefaultClient. Under
	// INTERNAL_TLS it is the mutual-TLS client pinned to this peer (ADR-0010).
	Client *http.Client
}

type emitEventRequestBody struct {
	ActorID      string            `json:"actor_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	Success      bool              `json:"success"`
}

func (c *AuditHTTPClient) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	return c.EmitEventWithDetails(ctx, actorID, action, resourceType, resourceID, nil, success)
}

func (c *AuditHTTPClient) EmitEventWithDetails(ctx context.Context, actorID, action, resourceType, resourceID string, details map[string]string, success bool) error {
	body, _ := json.Marshal(emitEventRequestBody{
		ActorID: actorID, Action: action, ResourceType: resourceType, ResourceID: resourceID, Details: details, Success: success,
	})
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

type attestRequestBody struct {
	SessionID      string `json:"session_id"`
	Revision       uint64 `json:"revision"`
	MetadataSHA256 string `json:"metadata_sha256"`
	KeyID          string `json:"key_id"`
}

// AttestMetadata tells the Audit Service that revision `revision` of the session's row, whose
// canonical form has the given SHA-256, is signed under keyID (ADR-0116 §3): it moves the session's
// independent head. A 409 is the head disagreeing — an older revision, another digest for the same
// one, or a jump: the row was taken back or changed, and that is domain.ErrMetadataIntegrity.
func (c *AuditHTTPClient) AttestMetadata(ctx context.Context, sessionID string, revision uint64, digest [32]byte, keyID string) error {
	body, _ := json.Marshal(attestRequestBody{SessionID: sessionID, Revision: revision, MetadataSHA256: hex.EncodeToString(digest[:]), KeyID: keyID})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.BaseURL+"/audit/v1/session-metadata/attestations", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := orDefault(c.Client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
		return nil
	case http.StatusConflict:
		return fmt.Errorf("%w: the audit's head refuses revision %d of session %s", domain.ErrMetadataIntegrity, revision, sessionID)
	default:
		return fmt.Errorf("session metadata attestation: status %d", resp.StatusCode)
	}
}

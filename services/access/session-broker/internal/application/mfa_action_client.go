package application

import (
	"context"
	"encoding/json"
)

// MFAActionBinding is reconstructed from the verified Gateway identity and the
// persisted session. It must never be populated from a client-supplied tuple.
type MFAActionBinding struct {
	ActorUserID string
	SessionID   string
	AccountID   string
	Protocol    string
	Action      string
}

type MFAActionStart struct {
	Challenge string          `json:"challenge"`
	ExpiresIn int             `json:"expires_in"`
	Factors   []string        `json:"factors"`
	WebAuthn  json.RawMessage `json:"webauthn,omitempty"`
}

type MFAActionProof struct {
	Challenge        string          `json:"challenge"`
	Factor           string          `json:"factor"`
	TOTPCode         string          `json:"totp_code,omitempty"`
	WebAuthnResponse json.RawMessage `json:"webauthn_response,omitempty"`
}

type MFAActionGrant struct {
	Grant     string `json:"grant"`
	ExpiresIn int    `json:"expires_in"`
}

// MFAActionClient is the Broker-only port to Authentication's action-bound
// step-up. The grant is a short-lived capability and must remain inside the
// Broker until the corresponding proxy action consumes it.
type MFAActionClient interface {
	Start(context.Context, MFAActionBinding) (MFAActionStart, error)
	Verify(context.Context, MFAActionBinding, MFAActionProof) (MFAActionGrant, error)
	Consume(context.Context, MFAActionBinding, string) error
}

func (s *SessionBrokerService) WithMFAActionClient(client MFAActionClient) *SessionBrokerService {
	s.mfaAction = client
	return s
}

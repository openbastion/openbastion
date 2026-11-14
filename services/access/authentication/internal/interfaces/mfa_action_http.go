package interfaces

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type actionRequestContext struct {
	ActorUserID string `json:"actor_user_id"`
}

type mfaActionStartRequest struct {
	Context   actionRequestContext `json:"context"`
	SessionID string               `json:"session_id"`
	AccountID string               `json:"account_id"`
	Protocol  string               `json:"protocol"`
	Action    string               `json:"action"`
}

type mfaActionStartResponse struct {
	Challenge string          `json:"challenge"`
	ExpiresIn int             `json:"expires_in"`
	Factors   []string        `json:"factors"`
	WebAuthn  json.RawMessage `json:"webauthn,omitempty"`
}

type mfaActionVerifyRequest struct {
	Context          actionRequestContext `json:"context"`
	SessionID        string               `json:"session_id"`
	AccountID        string               `json:"account_id"`
	Protocol         string               `json:"protocol"`
	Action           string               `json:"action"`
	Challenge        string               `json:"challenge"`
	Factor           string               `json:"factor"`
	TOTPCode         string               `json:"totp_code,omitempty"`
	WebAuthnResponse json.RawMessage      `json:"webauthn_response,omitempty"`
}

type mfaActionVerifyResponse struct {
	Grant     string `json:"grant"`
	ExpiresIn int    `json:"expires_in"`
}

type mfaActionConsumeResponse struct {
	Consumed bool `json:"consumed"`
}

type mfaActionConsumeRequest struct {
	Context   actionRequestContext `json:"context"`
	SessionID string               `json:"session_id"`
	AccountID string               `json:"account_id"`
	Protocol  string               `json:"protocol"`
	Action    string               `json:"action"`
	Grant     string               `json:"grant"`
}

// handleMFAActionStart is internal: CallerRules admits only the Session Broker.
// actor_user_id is the identity that the Gateway verified and the Broker forwards;
// the public client never calls this route or supplies that identity itself.
func (s *HTTPServer) handleMFAActionStart(w http.ResponseWriter, r *http.Request) {
	var req mfaActionStartRequest
	if !decodePost(w, r, &req) {
		return
	}
	result, err := s.svc.StartMFAActionStepUp(r.Context(), domain.MFAActionGrantBinding{
		UserID: req.Context.ActorUserID, SessionID: req.SessionID, AccountID: req.AccountID,
		Protocol: req.Protocol, Action: req.Action,
	})
	if err != nil {
		writeMFAActionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mfaActionStartResponse{
		Challenge: result.Challenge, ExpiresIn: int(result.ExpiresIn.Seconds()),
		Factors: result.Factors, WebAuthn: result.WebAuthn,
	})
}

// handleMFAActionVerify consumes a challenge and returns a single-action grant
// only to the Session Broker over the authenticated internal mTLS channel.
func (s *HTTPServer) handleMFAActionVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaActionVerifyRequest
	if !decodePost(w, r, &req) {
		return
	}
	result, err := s.svc.VerifyMFAActionStepUp(r.Context(), req.Challenge, domain.MFAActionGrantBinding{
		UserID: req.Context.ActorUserID, SessionID: req.SessionID, AccountID: req.AccountID,
		Protocol: req.Protocol, Action: req.Action,
	}, req.Factor, req.TOTPCode, req.WebAuthnResponse)
	if err != nil {
		writeMFAActionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mfaActionVerifyResponse{Grant: result.Grant, ExpiresIn: int(result.ExpiresIn.Seconds())})
}

func writeMFAActionError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrMFAActionRejected):
		http.Error(w, "the second factor was refused", http.StatusUnauthorized)
	case errors.Is(err, application.ErrMFAActionNotEnrolled):
		http.Error(w, "an eligible second factor is required", http.StatusForbidden)
	case errors.Is(err, application.ErrMFAActionStoreMissing), errors.Is(err, application.ErrAuditUnavailable):
		http.Error(w, "the action cannot be authorized now", http.StatusServiceUnavailable)
	default:
		if errors.Is(err, io.EOF) {
			http.Error(w, "the request body is empty", http.StatusBadRequest)
			return
		}
		http.Error(w, "the action cannot be authorized now", http.StatusServiceUnavailable)
	}
}

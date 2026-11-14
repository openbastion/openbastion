package interfaces

import (
	"encoding/json"
	"net/http"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// handleMFAActionConsume is internal to the Session Broker. It consumes the
// grant atomically and audits the consumption before returning success.
func (s *HTTPServer) handleMFAActionConsume(w http.ResponseWriter, r *http.Request) {
	var req mfaActionConsumeRequest
	if !decodePost(w, r, &req) {
		return
	}
	err := s.svc.ConsumeMFAActionGrant(r.Context(), req.Grant, domain.MFAActionGrantBinding{
		UserID: req.Context.ActorUserID, SessionID: req.SessionID, AccountID: req.AccountID,
		Protocol: req.Protocol, Action: req.Action,
	})
	if err != nil {
		writeMFAActionError(w, err)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(mfaActionConsumeResponse{Consumed: true})
}

package interfaces

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
)

// HTTPServer exposes ProxyControl.EstablishSession
// (proto/proxy/v1/proxy_control.proto, doc 07 §4) over JSON/HTTP — see
// /NOTES_SANDBOX.md for why HTTP stands in for gRPC here.
//
// This is the endpoint the Session Broker calls once it has already
// authorized a Vault scope (VaultAuthorization.AuthorizeScope). Note the
// Session Broker built earlier in this project does not call this
// endpoint yet — it still exposes its own internal/v1/authorize-connection
// as a stand-in — wiring the two together is the next increment.
type HTTPServer struct {
	pending *infrastructure.PendingSessions
	proxyEndpoint string
}

func NewHTTPServer(pending *infrastructure.PendingSessions, proxyEndpoint string) *HTTPServer {
	return &HTTPServer{pending: pending, proxyEndpoint: proxyEndpoint}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/establish-session", s.handleEstablishSession)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type establishSessionRequest struct {
	SessionID  string `json:"session_id"`
	TargetHost string `json:"target_host"`
	// TargetUser mirrors proto/proxy/v1/proxy_control.proto's
	// EstablishSessionRequest.target_user (doc 07 §4) and
	// privileged_accounts.username (doc 06 §3) — formalized in both
	// after having been threaded through this codec first; see
	// NOTES_SANDBOX.md for the history.
	TargetUser      string `json:"target_user"`
	VaultScopeToken string `json:"vault_scope_token"`
	TTLSeconds      int    `json:"ttl_seconds"`
}

type establishSessionResponse struct {
	ProxyEndpoint    string `json:"proxy_endpoint"`
	ConnectionTicket string `json:"connection_ticket"`
}

func (s *HTTPServer) handleEstablishSession(w http.ResponseWriter, r *http.Request) {
	var req establishSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	ticket := s.pending.Register(&infrastructure.PendingSession{
		SessionID:  req.SessionID,
		TargetHost: req.TargetHost,
		TargetUser: req.TargetUser,
		ScopeToken: req.VaultScopeToken,
		ExpiresAt:  time.Now().UTC().Add(ttl),
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(establishSessionResponse{
		ProxyEndpoint:    s.proxyEndpoint,
		ConnectionTicket: ticket,
	})
}

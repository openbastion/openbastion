package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
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
	pending       *infrastructure.PendingSessions
	proxyEndpoint string

	// Admit, when set, is asked before a ticket is issued: a session the
	// recording policy would refuse is refused here, with a 503, rather than
	// after the operator has been handed a ticket and opened a connection.
	// proxycore.Listener.Admit is the implementation. It is an early refusal,
	// not the guarantee: Serve asks again before it fetches the credential.
	//
	// breakGlass is the Broker's authorisation for a recording waiver (ADR-0009):
	// when set, and the proxy is configured to honour it, a recorder that is not
	// ready does not refuse the session.
	Admit func(ctx context.Context, sessionID string, breakGlass bool) error
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

	// BreakGlass mirrors EstablishSessionRequest.break_glass (doc 07 §4).
	BreakGlass bool `json:"break_glass"`
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
	if s.Admit != nil {
		if err := s.Admit(r.Context(), req.SessionID, req.BreakGlass); err != nil {
			if errors.Is(err, proxycore.ErrRecordingUnavailable) {
				// The cause stays in this log: the response travels back to
				// the operator, who needs the reason, not the recorder's address.
				log.Printf("ssh-proxy: session %s refused at establish-session: %v", req.SessionID, err)
				http.Error(w, "recording unavailable: the session was not started", http.StatusServiceUnavailable)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
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
		BreakGlass: req.BreakGlass,
	})

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(establishSessionResponse{
		ProxyEndpoint:    s.proxyEndpoint,
		ConnectionTicket: ticket,
	})
}

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
// (proto/proxy/v1/proxy_control.proto, docs/api/grpc/README.md §4) over JSON/HTTP — see
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

	// Live is the registry of the connections this proxy serves and of the
	// sessions it was told to cut (ADR-0018): the same one as its Listener's.
	// Without it the revoke-session route answers 503 and nothing is established.
	Live *proxycore.LiveSessions

	// RevokeWait bounds how long revoke-session waits for the connections it cut to
	// stop carrying anything; zero means DefaultRevokeWait.
	RevokeWait time.Duration
}

// DefaultRevokeWait is how long a revocation waits for the open connections of the
// session to close before it says it could not finish.
const DefaultRevokeWait = 5 * time.Second

// MaxRevocationMemory bounds how long the proxy remembers a revoked session,
// whatever it is asked: the Broker sends the time the session had left, which is
// never longer than the longest session it grants.
const MaxRevocationMemory = 7 * 24 * time.Hour

func NewHTTPServer(pending *infrastructure.PendingSessions, proxyEndpoint string) *HTTPServer {
	return &HTTPServer{pending: pending, proxyEndpoint: proxyEndpoint}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/establish-session", s.handleEstablishSession)
	mux.HandleFunc("/internal/v1/revoke-session", s.handleRevokeSession)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type establishSessionRequest struct {
	SessionID  string `json:"session_id"`
	TargetHost string `json:"target_host"`
	Protocol   string `json:"protocol"`
	// TargetUser mirrors proto/proxy/v1/proxy_control.proto's
	// EstablishSessionRequest.target_user (docs/api/grpc/README.md §4) and
	// privileged_accounts.username (docs/architecture/data-architecture.md §3) — formalized in both
	// after having been threaded through this codec first; see
	// NOTES_SANDBOX.md for the history.
	TargetUser      string `json:"target_user"`
	VaultScopeToken string `json:"vault_scope_token"`
	TTLSeconds      int    `json:"ttl_seconds"`

	// BreakGlass mirrors EstablishSessionRequest.break_glass (docs/api/grpc/README.md §4).
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
	if req.Protocol != "" && req.Protocol != "ssh" {
		http.Error(w, "unsupported session protocol", http.StatusConflict)
		return
	}
	if s.Live == nil {
		http.Error(w, "revocation unavailable: the session was not started", http.StatusServiceUnavailable)
		return
	}
	// A session the Broker has ended gets no ticket (ADR-0018): this is how a connect
	// that was in flight when the session was ended leaves nothing behind.
	if s.Live.Revoked(req.SessionID) {
		http.Error(w, "session revoked: it was ended and cannot be established", http.StatusConflict)
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
	// The check above and the registration are not one step; a revocation that
	// landed between them did not see this ticket. Look again, and take it back.
	if s.Live.Revoked(req.SessionID) {
		s.pending.RevokeSession(req.SessionID)
		http.Error(w, "session revoked: it was ended and cannot be established", http.StatusConflict)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(establishSessionResponse{
		ProxyEndpoint:    s.proxyEndpoint,
		ConnectionTicket: ticket,
	})
}

type revokeSessionRequest struct {
	SessionID string `json:"session_id"`
	// TTLSeconds is how long the proxy remembers the revocation: the time the session
	// had left. After that nothing can be established for it, and there is nothing
	// left to refuse.
	TTLSeconds int `json:"ttl_seconds"`
}

type revokeSessionResponse struct {
	TicketsRevoked int `json:"tickets_revoked"`
	ConnectionsCut int `json:"connections_cut"`
}

// handleRevokeSession is what makes a session ended at the Broker end at the proxy
// (ADR-0018). In this order: remember the revocation and signal every open
// connection of the session to stop, drop its unused tickets, then wait — a few
// seconds at most — for the connections to close. 200 means the session cannot
// carry anything any more; anything else means the Broker must not say it was ended.
//
// It is idempotent: a session the proxy knows nothing of is a 200 with nothing cut,
// and a second call finishes what a first could not.
func (s *HTTPServer) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeSessionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad request: a JSON body with session_id and ttl_seconds is expected", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || req.TTLSeconds <= 0 {
		http.Error(w, "bad request: session_id and a positive ttl_seconds are expected", http.StatusBadRequest)
		return
	}
	if s.Live == nil {
		http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
		return
	}
	// Compared in seconds, before converting: a huge number of seconds overflows a Duration
	// into a negative one, which would be a revocation that is forgotten at once.
	memory := MaxRevocationMemory
	if req.TTLSeconds < int(MaxRevocationMemory/time.Second) {
		memory = time.Duration(req.TTLSeconds) * time.Second
	}
	wait := s.RevokeWait
	if wait <= 0 {
		wait = DefaultRevokeWait
	}

	// The memory of the revocation first: from this instant a connection that
	// registers is refused, and every open one is told to stop. Then the tickets
	// nobody used. Then wait for the connections to be closed.
	revocation := s.Live.Revoke(req.SessionID, time.Now().Add(memory))
	tickets := s.pending.RevokeSession(req.SessionID)
	cut := revocation.Cut()
	stillOpen := revocation.Wait(wait)
	if stillOpen > 0 {
		log.Printf("ssh-proxy: revocation of session %s: %d connection(s) were signalled but are still closing after %s", req.SessionID, stillOpen, wait)
		http.Error(w, "the session was signalled to stop but some connections are still closing: try again", http.StatusServiceUnavailable)
		return
	}
	log.Printf("ssh-proxy: session %s revoked: %d connection(s) cut, %d ticket(s) revoked", req.SessionID, cut, tickets)
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(revokeSessionResponse{TicketsRevoked: tickets, ConnectionsCut: cut})
}

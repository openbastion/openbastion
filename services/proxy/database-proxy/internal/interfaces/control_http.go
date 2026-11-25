package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/database-proxy/internal/domain"
)

const (
	DefaultRevokeWait   = 5 * time.Second
	MaxRevocationMemory = 7 * 24 * time.Hour
	MaxSessionTTL       = 12 * time.Hour
	maxControlBodyBytes = 16 << 10
)

// SessionAdmitter is the recording gate. The zero value is deliberately not
// permissive: without an admission decision, the proxy cannot issue a ticket.
type SessionAdmitter func(ctx context.Context, sessionID string, breakGlass bool) error

type HTTPServer struct {
	pending       *domain.TicketStore
	live          *proxycore.LiveSessions
	proxyEndpoint string
	admit         SessionAdmitter
	RevokeWait    time.Duration
}

func NewHTTPServer(pending *domain.TicketStore, live *proxycore.LiveSessions, proxyEndpoint string, admit SessionAdmitter) *HTTPServer {
	return &HTTPServer{pending: pending, live: live, proxyEndpoint: proxyEndpoint, admit: admit}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/internal/v1/establish-session", s.handleEstablishSession)
	mux.HandleFunc("/internal/v1/revoke-session", s.handleRevokeSession)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func CallerRules() []mtls.Rule {
	return []mtls.Rule{
		{Method: http.MethodPost, Path: "/internal/v1/establish-session", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodPost, Path: "/internal/v1/revoke-session", Callers: []string{mtls.SessionBroker}},
		{Method: http.MethodGet, Path: "/healthz", Callers: []string{mtls.Any}},
	}
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.WriteHeader(http.StatusOK)
}

type establishSessionRequest struct {
	SessionID       string `json:"session_id"`
	ActorID         string `json:"actor_id"`
	TargetHost      string `json:"target_host"`
	TargetUser      string `json:"target_user"`
	VaultScopeToken string `json:"vault_scope_token"`
	TTLSeconds      int    `json:"ttl_seconds"`
	BreakGlass      bool   `json:"break_glass"`
}

type establishSessionResponse struct {
	ProxyEndpoint    string `json:"proxy_endpoint"`
	ConnectionTicket string `json:"connection_ticket"`
}

func (s *HTTPServer) handleEstablishSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	var req establishSessionRequest
	if err := decodeStrictJSON(w, r, &req); err != nil {
		http.Error(w, "invalid establish-session request", http.StatusBadRequest)
		return
	}
	if req.SessionID == "" || req.ActorID == "" || req.TargetHost == "" || req.TargetUser == "" || req.VaultScopeToken == "" || req.TTLSeconds < 1 || time.Duration(req.TTLSeconds)*time.Second > MaxSessionTTL {
		http.Error(w, "invalid establish-session request", http.StatusBadRequest)
		return
	}
	if s.pending == nil || s.live == nil || s.proxyEndpoint == "" || s.admit == nil {
		http.Error(w, "session establishment unavailable", http.StatusServiceUnavailable)
		return
	}
	if s.live.Revoked(req.SessionID) {
		http.Error(w, "session revoked", http.StatusConflict)
		return
	}
	if err := s.admit(r.Context(), req.SessionID, req.BreakGlass); err != nil {
		if errors.Is(err, proxycore.ErrRecordingUnavailable) {
			log.Printf("database-proxy: session %s refused at establish-session: %v", req.SessionID, err)
		}
		http.Error(w, "recording unavailable: the session was not started", http.StatusServiceUnavailable)
		return
	}
	expiresAt := time.Now().UTC().Add(time.Duration(req.TTLSeconds) * time.Second)
	ticket, err := s.pending.Register(domain.PendingSession{
		SessionID:  req.SessionID,
		ActorID:    req.ActorID,
		TargetHost: req.TargetHost,
		TargetUser: req.TargetUser,
		ScopeToken: []byte(req.VaultScopeToken),
		ExpiresAt:  expiresAt,
		BreakGlass: req.BreakGlass,
	})
	if err != nil {
		if errors.Is(err, domain.ErrTicketCapacity) {
			http.Error(w, "session establishment capacity reached", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, "session cannot be established", http.StatusConflict)
		return
	}
	// A revocation may have landed between the first check and ticket registration.
	if s.live.Revoked(req.SessionID) {
		s.pending.RevokeSession(req.SessionID, expiresAt)
		http.Error(w, "session revoked", http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(establishSessionResponse{ProxyEndpoint: s.proxyEndpoint, ConnectionTicket: ticket})
}

type revokeSessionRequest struct {
	SessionID  string `json:"session_id"`
	TTLSeconds int    `json:"ttl_seconds"`
}

type revokeSessionResponse struct {
	TicketsRevoked int `json:"tickets_revoked"`
	ConnectionsCut int `json:"connections_cut"`
}

func (s *HTTPServer) handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req revokeSessionRequest
	if err := decodeStrictJSON(w, r, &req); err != nil || req.SessionID == "" || req.TTLSeconds < 1 {
		http.Error(w, "invalid revoke-session request", http.StatusBadRequest)
		return
	}
	if s.pending == nil || s.live == nil {
		http.Error(w, "revocation unavailable", http.StatusServiceUnavailable)
		return
	}
	memory := MaxRevocationMemory
	if time.Duration(req.TTLSeconds)*time.Second < memory {
		memory = time.Duration(req.TTLSeconds) * time.Second
	}
	until := time.Now().UTC().Add(memory)
	revocation := s.live.Revoke(req.SessionID, until)
	tickets := s.pending.RevokeSession(req.SessionID, until)
	wait := s.RevokeWait
	if wait <= 0 {
		wait = DefaultRevokeWait
	}
	cut := revocation.Cut()
	if stillOpen := revocation.Wait(wait); stillOpen > 0 {
		log.Printf("database-proxy: revocation of session %s: %d connection(s) remain open after %s", req.SessionID, stillOpen, wait)
		http.Error(w, "the session was signalled to stop but some connections are still closing: try again", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(revokeSessionResponse{TicketsRevoked: tickets, ConnectionsCut: cut})
}

func decodeStrictJSON(w http.ResponseWriter, r *http.Request, dst any) error {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxControlBodyBytes))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return errors.New("request contains trailing JSON")
	}
	return nil
}

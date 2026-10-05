// Package interfaces exposes SessionOrchestration
// (proto/access/v1/session_orchestration.proto) plus the Connect flow
// (doc 05 §2, POST /sessions/{id}/connect) over JSON/HTTP — see
// /NOTES_SANDBOX.md for why HTTP stands in for gRPC here.
//
// Every route under /sessions/* is safe to expose through the API Gateway
// to end clients — including /connect, now that it returns only a
// connection ticket (never the Vault scope token used to obtain it, see
// application.SessionBrokerService.Connect's doc comment). Earlier in
// this project's history this endpoint lived under /internal/v1/ for
// exactly that reason, before ssh-proxy existed to mint a real ticket —
// see NOTES_SANDBOX.md for that history.
package interfaces

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type HTTPServer struct {
	svc *application.SessionBrokerService
}

func NewHTTPServer(svc *application.SessionBrokerService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", s.handleSessionsCollection)
	mux.HandleFunc("/sessions/", s.handleSessionItem) // /sessions/{id}, /sessions/{id}/connect
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- POST /sessions (mirrors doc 05 §2) ---------------------------------

type createSessionRequest struct {
	RequestedBy         string   `json:"requestedBy"`
	ActorRoles          []string `json:"actorRoles"`
	PrivilegedAccountID string   `json:"targetAccountId"`
	Protocol            string   `json:"protocol"`
	Justification       string   `json:"justification"`
	DurationMinutes     int      `json:"durationMinutes"`
}

type sessionResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	Protocol            string `json:"protocol"`
	RequestedBy         string `json:"requestedBy"`
	PrivilegedAccountID string `json:"privilegedAccountId"`
	Justification       string `json:"justification"`
}

func toSessionResponse(s *domain.Session) sessionResponse {
	return sessionResponse{
		ID: s.ID, Status: string(s.Status), Protocol: s.Protocol,
		RequestedBy: s.RequestedBy, PrivilegedAccountID: s.PrivilegedAccountID,
		Justification: s.Justification,
	}
}

func (s *HTTPServer) handleSessionsCollection(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	sess, err := s.svc.CreateSession(r.Context(), req.RequestedBy, req.ActorRoles, req.PrivilegedAccountID, req.Protocol, req.Justification, req.DurationMinutes)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
}

// -- GET /sessions/{id}, DELETE /sessions/{id}, POST /sessions/{id}/connect --

func (s *HTTPServer) handleSessionItem(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path[len("/sessions/"):]
	if rest == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}

	if id, ok := strings.CutSuffix(rest, "/connect"); ok {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		s.handleConnect(w, r, id)
		return
	}

	id := rest
	switch r.Method {
	case http.MethodGet:
		sess, err := s.svc.GetSession(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
	case http.MethodDelete:
		sess, err := s.svc.TerminateSession(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// -- POST /sessions/{id}/connect (mirrors doc 05 §2, ConnectionTicket) --

type connectionTicketResponse struct {
	ProxyEndpoint string `json:"proxyEndpoint"`
	Ticket        string `json:"ticket"`
}

func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request, sessionID string) {
	proxyEndpoint, ticket, _, err := s.svc.Connect(r.Context(), sessionID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(connectionTicketResponse{ProxyEndpoint: proxyEndpoint, Ticket: ticket})
}

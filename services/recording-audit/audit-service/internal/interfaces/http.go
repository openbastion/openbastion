// Package interfaces exposes AuditIngestion (proto/audit/v1/audit.proto)
// over JSON/HTTP. See password-vault/internal/interfaces/http.go for the
// sandbox network note this mirrors.
package interfaces

import (
	"encoding/json"
	"net/http"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
)

type HTTPServer struct {
	svc *application.AuditService
}

func NewHTTPServer(svc *application.AuditService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/audit/v1/emit-event", s.handleEmitEvent)
	mux.HandleFunc("/audit/v1/verify-chain", s.handleVerifyChain)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

type emitEventRequest struct {
	ActorID      string `json:"actor_id"`
	Action       string `json:"action"`
	ResourceType string `json:"resource_type"`
	ResourceID   string `json:"resource_id"`
	Success      bool   `json:"success"`
}

type emitEventResponse struct {
	EventID string `json:"event_id"`
}

func (s *HTTPServer) handleEmitEvent(w http.ResponseWriter, r *http.Request) {
	var req emitEventRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	event, err := s.svc.EmitEvent(r.Context(), req.ActorID, req.Action, req.ResourceType, req.ResourceID, req.Success)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(emitEventResponse{EventID: event.ID})
}

func (s *HTTPServer) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.VerifyChain(r.Context()); err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}

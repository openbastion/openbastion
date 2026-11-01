// Package interfaces exposes AuditIngestion (proto/audit/v1/audit.proto)
// over JSON/HTTP. See password-vault/internal/interfaces/http.go for the
// sandbox network note this mirrors.
package interfaces

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

// maxEventBodyBytes bounds an emit-event body (ADR-0025): the largest event the bounds allow
// is well under 2 KiB of JSON, escapes included; 16 KiB leaves room without being unlimited.
const maxEventBodyBytes = 16 << 10

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
	ActorID      string            `json:"actor_id"`
	Action       string            `json:"action"`
	ResourceType string            `json:"resource_type"`
	ResourceID   string            `json:"resource_id"`
	Details      map[string]string `json:"details,omitempty"`
	Success      bool              `json:"success"`
}

type emitEventResponse struct {
	EventID string `json:"event_id"`
}

func (s *HTTPServer) handleEmitEvent(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req emitEventRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxEventBodyBytes)).Decode(&req); err != nil {
		var tooBig *http.MaxBytesError
		if errors.As(err, &tooBig) {
			http.Error(w, "event too large", http.StatusRequestEntityTooLarge)
			return
		}
		// The decoder's message can quote what was sent: it is not repeated.
		http.Error(w, "invalid event: not a JSON event", http.StatusBadRequest)
		return
	}
	// Who wrote it is the certificate's, never the body's (ADR-0027): empty without internal TLS.
	emitter, _ := mtls.CallerFrom(r.Context())
	event, err := s.svc.EmitEventAsWithDetails(r.Context(), emitter, req.ActorID, req.Action, req.ResourceType, req.ResourceID, req.Details, req.Success)
	if err != nil {
		if errors.Is(err, domain.ErrInvalidEvent) {
			// Names the field and the rule, never the value.
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		// The store's error can name addresses and tables: it stays in this log.
		log.Printf("audit-service: an event could not be appended: %v", err)
		http.Error(w, "the event could not be appended", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(emitEventResponse{EventID: event.ID})
}

func (s *HTTPServer) handleVerifyChain(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.VerifyChain(r.Context()); err != nil {
		if errors.Is(err, domain.ErrAnchorsUnavailable) {
			// Not a verdict of tampering: the chain cannot be vouched for (ADR-0028). The cause
			// (a path) stays in this log.
			log.Printf("audit-service: verifying the chain: %v", err)
			http.Error(w, "the anchors of the chain cannot be read: the chain cannot be vouched for", http.StatusServiceUnavailable)
			return
		}
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	w.WriteHeader(http.StatusOK)
}

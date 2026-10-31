// Package interfaces exposes Authorization.CheckAccess
// (proto/authz/v1/authorization.proto) and policy management over
// JSON/HTTP. See password-vault/internal/interfaces/http.go for the
// sandbox network note this mirrors.
package interfaces

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

type HTTPServer struct {
	svc *application.AuthorizationService
}

func NewHTTPServer(svc *application.AuthorizationService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/authz/v1/policies", s.handleCreatePolicy)
	mux.HandleFunc("/authz/v1/check-access", s.handleCheckAccess)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- policies (mirrors POST /policies, docs/api/rest/openapi.yaml) ---------------------

type createPolicyRequest struct {
	Name            string   `json:"name"`
	Role            string   `json:"role"`
	ResourcePattern string   `json:"resourcePattern"`
	Effect          string   `json:"effect"`
	CreatedBy       string   `json:"createdBy"`
	ActorRoles      []string `json:"actorRoles"`
}

type createPolicyResponse struct {
	ID string `json:"id"`
}

func (s *HTTPServer) handleCreatePolicy(w http.ResponseWriter, r *http.Request) {
	var req createPolicyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	p, err := s.svc.CreatePolicy(r.Context(), req.ActorRoles, req.Name, req.Role, req.ResourcePattern, domain.Effect(req.Effect), req.CreatedBy)
	if err != nil {
		// A refusal says why; a duplicate is a conflict; anything else is the store failing —
		// a 503 whose cause stays in this log (ADR-0043): the Gateway relays this body.
		switch {
		case errors.Is(err, application.ErrAccessDenied):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, domain.ErrAlreadyExists):
			http.Error(w, domain.ErrAlreadyExists.Error(), http.StatusConflict)
		default:
			log.Printf("authorization: creating a policy failed: %v", err)
			http.Error(w, "the policy was not created: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createPolicyResponse{ID: p.ID})
}

// -- check-access (Authorization.CheckAccess, docs/api/grpc/README.md §8) ---------------

type checkAccessRequest struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type checkAccessResponse struct {
	Allowed          bool   `json:"allowed"`
	RequiresApproval bool   `json:"requires_approval"`
	DecisionReason   string `json:"decision_reason"`
}

func (s *HTTPServer) handleCheckAccess(w http.ResponseWriter, r *http.Request) {
	var req checkAccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	decision, err := s.svc.CheckAccess(r.Context(), req.ActorRoles, req.Resource, req.Action)
	if err != nil {
		log.Printf("authorization: check-access failed: %v", err)
		http.Error(w, "the access decision could not be made", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(checkAccessResponse{
		Allowed: decision.Allowed, RequiresApproval: decision.RequiresApproval, DecisionReason: decision.Reason,
	})
}

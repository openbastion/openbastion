// Package interfaces exposes Authorization.CheckAccess
// (proto/authz/v1/authorization.proto) and policy management over
// JSON/HTTP. See password-vault/internal/interfaces/http.go for the
// sandbox network note this mirrors.
package interfaces

import (
	"encoding/json"
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

// -- policies (mirrors POST /policies, doc 05 §2) ---------------------

type createPolicyRequest struct {
	Name            string `json:"name"`
	Role            string `json:"role"`
	ResourcePattern string `json:"resourcePattern"`
	Effect          string `json:"effect"`
	CreatedBy       string `json:"createdBy"`
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
	p, err := s.svc.CreatePolicy(r.Context(), req.Name, req.Role, req.ResourcePattern, domain.Effect(req.Effect), req.CreatedBy)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createPolicyResponse{ID: p.ID})
}

// -- check-access (Authorization.CheckAccess, doc 07 §8) ---------------

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
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(checkAccessResponse{
		Allowed: decision.Allowed, RequiresApproval: decision.RequiresApproval, DecisionReason: decision.Reason,
	})
}

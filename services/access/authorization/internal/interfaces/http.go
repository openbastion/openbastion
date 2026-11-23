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
	mux.HandleFunc("/authz/v1/capabilities", s.handleCapabilities)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- policies (mirrors POST /policies, docs/api/rest/openapi.yaml) ---------------------

type createPolicyRequest struct {
	Name            string          `json:"name"`
	Role            string          `json:"role"`
	ResourcePattern string          `json:"resourcePattern"`
	ActionPattern   json.RawMessage `json:"actionPattern"`
	Effect          string          `json:"effect"`
	CreatedBy       string          `json:"createdBy"`
	ActorRoles      []string        `json:"actorRoles"`
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
	// Every policy must declare its action scope. A wildcard remains available only
	// when an administrator explicitly requests it; omission must never widen access.
	var actionPattern string
	if len(req.ActionPattern) == 0 || json.Unmarshal(req.ActionPattern, &actionPattern) != nil || actionPattern == "" {
		http.Error(w, domain.ErrInvalidPolicyPattern.Error(), http.StatusBadRequest)
		return
	}
	p, err := s.svc.CreatePolicy(r.Context(), req.ActorRoles, req.Name, req.Role, req.ResourcePattern, actionPattern, domain.Effect(req.Effect), req.CreatedBy)
	if err != nil {
		// A refusal says why; a duplicate is a conflict; anything else is the store failing —
		// a 503 whose cause stays in this log (ADR-0043): the Gateway relays this body.
		switch {
		case errors.Is(err, application.ErrAccessDenied):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, domain.ErrAlreadyExists):
			http.Error(w, domain.ErrAlreadyExists.Error(), http.StatusConflict)
		case errors.Is(err, domain.ErrInvalidPolicyPattern):
			http.Error(w, domain.ErrInvalidPolicyPattern.Error(), http.StatusBadRequest)
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

// -- capabilities (ADR-0131) -----------------------------------------------------------------

// maxCapabilitiesBody bounds the request: 32 questions of 2 × 256 bytes fit well inside it.
const maxCapabilitiesBody = 32 << 10

type capabilityQueryJSON struct {
	Resource string `json:"resource"`
	Action   string `json:"action"`
	Prefix   bool   `json:"prefix"`
}

type capabilitiesRequest struct {
	ActorRoles []string              `json:"actor_roles"`
	Queries    []capabilityQueryJSON `json:"queries"`
}

type capabilitiesResponse struct {
	Allowed []bool `json:"allowed"`
}

// handleCapabilities answers the Gateway's closed list of Admin UI questions for one caller's
// roles (ADR-0131): booleans in the order asked, never a reason, never a policy. A malformed or
// unbounded list is a 400; a failing store a 503 that says nothing of it.
func (s *HTTPServer) handleCapabilities(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req capabilitiesRequest
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxCapabilitiesBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "invalid capabilities request", http.StatusBadRequest)
		return
	}
	queries := make([]application.CapabilityQuery, len(req.Queries))
	for i, q := range req.Queries {
		queries[i] = application.CapabilityQuery{Resource: q.Resource, Action: q.Action, Prefix: q.Prefix}
	}
	allowed, err := s.svc.Capabilities(r.Context(), req.ActorRoles, queries)
	if errors.Is(err, application.ErrInvalidCapabilityQuery) {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err != nil {
		log.Printf("authorization: capabilities failed: %v", err)
		http.Error(w, "the capabilities could not be evaluated", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(capabilitiesResponse{Allowed: allowed})
}

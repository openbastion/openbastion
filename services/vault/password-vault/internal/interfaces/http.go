// Package interfaces exposes VaultAuthorization and VaultCredentialIssuance
// (proto/vault/v1/vault.proto) over JSON/HTTP.
//
// SANDBOX NOTE: this project's internal transport is specified as gRPC
// (OpenBastion_07_Interfaces_Inter_Services.md). google.golang.org/grpc and
// google.golang.org/protobuf could not be fetched in this build sandbox —
// see /NOTES_SANDBOX.md at the repo root for the exact network constraint.
// This HTTP/JSON layer implements the same request/response shapes as the
// .proto messages, field for field, so it can be swapped for generated
// gRPC code later without touching internal/application or internal/domain.
package interfaces

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

type HTTPServer struct {
	svc *application.VaultService
}

func NewHTTPServer(svc *application.VaultService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/vault/v1/onboard-account", s.handleOnboardAccount)
	mux.HandleFunc("/vault/v1/rotate", s.handleRotate)
	mux.HandleFunc("/vault/v1/authorize-scope", s.handleAuthorizeScope)
	mux.HandleFunc("/vault/v1/fetch-credential", s.handleFetchCredential)
	mux.HandleFunc("/vault/v1/accounts", s.handleListAccounts) // exact path — distinct ServeMux pattern from the subtree below
	mux.HandleFunc("/vault/v1/accounts/", s.handleAccountItem) // subtree — GET and DELETE by id
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- onboard-account (mirrors POST /vault/accounts, doc 05 §2) -------------

type onboardAccountRequest struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Username       string   `json:"username"`
	TargetHost     string   `json:"targetHost"`
	Protocol       string   `json:"protocol"`
	RotationPolicy string   `json:"rotationPolicy"`
	InitialSecret  []byte   `json:"initialSecret"`
	ActorRoles     []string `json:"actorRoles"`
}

func (s *HTTPServer) handleOnboardAccount(w http.ResponseWriter, r *http.Request) {
	var req onboardAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.svc.OnboardAccount(r.Context(), req.ActorRoles, req.ID, req.Name, req.Username, req.TargetHost, req.Protocol,
		domain.RotationPolicy(req.RotationPolicy), req.InitialSecret)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// -- rotate (mirrors POST /vault/accounts/{id}/rotate, doc 05 §2) ---------

type rotateRequest struct {
	AccountID  string   `json:"accountId"`
	NewSecret  []byte   `json:"newSecret"`
	ActorRoles []string `json:"actorRoles"`
}

func (s *HTTPServer) handleRotate(w http.ResponseWriter, r *http.Request) {
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.Rotate(r.Context(), req.ActorRoles, req.AccountID, req.NewSecret); err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// -- authorize-scope (VaultAuthorization.AuthorizeScope) -------------------

type authorizeScopeRequest struct {
	SessionID           string `json:"session_id"`
	PrivilegedAccountID string `json:"privileged_account_id"`
	ProxyServiceID      string `json:"proxy_service_id"`
	TTLSeconds          int    `json:"ttl_seconds"`
}

type authorizeScopeResponse struct {
	ScopeToken string    `json:"scope_token"`
	ExpiresAt  time.Time `json:"expires_at"`
}

func (s *HTTPServer) handleAuthorizeScope(w http.ResponseWriter, r *http.Request) {
	var req authorizeScopeRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	ttl := time.Duration(req.TTLSeconds) * time.Second
	token, expiresAt, err := s.svc.AuthorizeScope(r.Context(), req.SessionID, req.PrivilegedAccountID, req.ProxyServiceID, ttl)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, authorizeScopeResponse{ScopeToken: token, ExpiresAt: expiresAt})
}

// -- fetch-credential (VaultCredentialIssuance.FetchCredential) ------------
//
// The single endpoint in the whole system that returns secret material —
// ADR-0003. Called only by a proxy, never by the control plane.

type fetchCredentialRequest struct {
	ScopeToken     string `json:"scope_token"`
	CallingProxyID string `json:"calling_proxy_id"`
}

type fetchCredentialResponse struct {
	CredentialType     string `json:"credential_type"`
	CredentialMaterial []byte `json:"credential_material"`
}

func (s *HTTPServer) handleFetchCredential(w http.ResponseWriter, r *http.Request) {
	var req fetchCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	credType, material, err := s.svc.FetchCredential(r.Context(), req.ScopeToken, req.CallingProxyID)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	writeJSON(w, fetchCredentialResponse{CredentialType: credType, CredentialMaterial: material})
}

// -- GET /vault/v1/accounts/{id}, DELETE /vault/v1/accounts/{id} -----------
// (mirrors GET and DELETE /vault/accounts/{id}, doc 05 §2)
//
// Metadata only — target host, username, protocol — never a secret, not
// even encrypted. GET is what the Session Broker calls to resolve where
// and as whom to connect, before ever touching the Vault's scope/credential
// endpoints; it returns 404 for a disabled account exactly as for an
// unknown one (application.VaultService.GetAccount), which is what makes
// DELETE below actually block new sessions against the account it disabled.

type accountResponse struct {
	ID         string     `json:"id"`
	Name       string     `json:"name"`
	Username   string     `json:"username"`
	TargetHost string     `json:"targetHost"`
	Protocol   string     `json:"protocol"`
	DisabledAt *time.Time `json:"disabledAt,omitempty"`
}

func (s *HTTPServer) handleAccountItem(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/vault/v1/accounts/"):]
	if id == "" {
		http.Error(w, "missing account id", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		account, err := s.svc.GetAccount(r.Context(), id)
		if err != nil {
			http.Error(w, err.Error(), http.StatusNotFound)
			return
		}
		writeJSON(w, accountResponse{
			ID: account.ID, Name: account.Name, Username: account.Username,
			TargetHost: account.TargetHost, Protocol: account.Protocol, DisabledAt: account.DisabledAt,
		})

	case http.MethodDelete:
		// actorRoles travels in the query string, not a JSON body — a
		// DELETE conventionally carries none, unlike onboard/rotate's
		// POST bodies. The Gateway builds this same query parameter
		// (api-gateway/internal/interfaces/http.go).
		actorRoles := splitCommaList(r.URL.Query().Get("actorRoles"))
		if err := s.svc.DisableAccount(r.Context(), actorRoles, id); err != nil {
			if err == domain.ErrNotFound {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// -- GET /vault/v1/accounts (mirrors GET /vault/accounts, doc 05 §2) -------

type listAccountsResponse struct {
	Items      []accountResponse `json:"items"`
	Page       int               `json:"page"`
	PageSize   int               `json:"pageSize"`
	TotalItems int               `json:"totalItems"`
}

func (s *HTTPServer) handleListAccounts(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))
	actorRoles := splitCommaList(q.Get("actorRoles"))

	// Clamping (page < 1 → 1, pageSize out of [1,100] → defaulted) happens
	// in application.VaultService.ListAccounts, not here — see its doc
	// comment. A missing or unparsable query param becomes 0, which that
	// clamping also handles correctly (0 < minPage/minPageSize).
	accounts, totalItems, err := s.svc.ListAccounts(r.Context(), actorRoles, page, pageSize)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}

	items := make([]accountResponse, 0, len(accounts))
	for _, a := range accounts {
		items = append(items, accountResponse{
			ID: a.ID, Name: a.Name, Username: a.Username,
			TargetHost: a.TargetHost, Protocol: a.Protocol, DisabledAt: a.DisabledAt,
		})
	}
	writeJSON(w, listAccountsResponse{Items: items, Page: page, PageSize: pageSize, TotalItems: totalItems})
}

func splitCommaList(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

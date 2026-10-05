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
	mux.HandleFunc("/vault/v1/accounts/", s.handleGetAccount)
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

// -- GET /vault/v1/accounts/{id} (mirrors GET /vault/accounts/{id}, doc 05 §2) --
//
// Metadata only — target host, username, protocol — never a secret, not
// even encrypted. This is what the Session Broker calls to resolve where
// and as whom to connect, before ever touching the Vault's scope/credential
// endpoints.

type accountResponse struct {
	ID         string `json:"id"`
	Name       string `json:"name"`
	Username   string `json:"username"`
	TargetHost string `json:"targetHost"`
	Protocol   string `json:"protocol"`
}

func (s *HTTPServer) handleGetAccount(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/vault/v1/accounts/"):]
	if id == "" {
		http.Error(w, "missing account id", http.StatusBadRequest)
		return
	}
	account, err := s.svc.GetAccount(r.Context(), id)
	if err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	writeJSON(w, accountResponse{
		ID: account.ID, Name: account.Name, Username: account.Username,
		TargetHost: account.TargetHost, Protocol: account.Protocol,
	})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

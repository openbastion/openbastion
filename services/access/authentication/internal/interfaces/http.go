// Package interfaces exposes user onboarding, POST /auth/login (docs/api/rest/openapi.yaml
// §2) and token verification over JSON/HTTP — see
// password-vault/internal/interfaces/http.go for the sandbox network
// note this mirrors.
package interfaces

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
)

type HTTPServer struct {
	svc *application.AuthenticationService
}

func NewHTTPServer(svc *application.AuthenticationService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/users", s.handleCreateUser)
	mux.HandleFunc("/auth/v1/login", s.handleLogin)
	mux.HandleFunc("/auth/v1/verify", s.handleVerify)
	mux.HandleFunc("/auth/v1/oidc/start", s.handleOIDCStart)
	mux.HandleFunc("/auth/v1/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/auth/v1/ldap", s.handleLDAPInfo)
	mux.HandleFunc("/auth/v1/ldap/login", s.handleLDAPLogin)
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- POST /auth/v1/users — onboarding, admin-only in a real deployment --

type createUserRequest struct {
	Username    string   `json:"username"`
	DisplayName string   `json:"displayName"`
	Password    string   `json:"password"`
	Roles       []string `json:"roles"`
}

type createUserResponse struct {
	ID string `json:"id"`
}

func (s *HTTPServer) handleCreateUser(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	u, err := s.svc.CreateUser(r.Context(), req.Username, req.DisplayName, req.Password, req.Roles)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(createUserResponse{ID: u.ID})
}

// -- POST /auth/v1/login (mirrors POST /auth/login, docs/api/rest/openapi.yaml) ---------

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type loginResponse struct {
	AccessToken string `json:"accessToken"`
	ExpiresIn   int    `json:"expiresIn"`
}

func (s *HTTPServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	token, ttl, err := s.svc.Login(r.Context(), req.Username, req.Password)
	if err != nil {
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{AccessToken: token, ExpiresIn: int(ttl.Seconds())})
}

// -- POST /auth/v1/verify — internal, called by the API Gateway ---------

type verifyRequest struct {
	Token string `json:"token"`
}

type verifyResponse struct {
	UserID   string   `json:"userId"`
	Username string   `json:"username"`
	Roles    []string `json:"roles"`
}

func (s *HTTPServer) handleVerify(w http.ResponseWriter, r *http.Request) {
	var req verifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	userID, username, roles, err := s.svc.VerifyToken(r.Context(), req.Token)
	if err != nil {
		http.Error(w, "invalid token", http.StatusUnauthorized)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(verifyResponse{UserID: userID, Username: username, Roles: roles})
}

// -- POST /auth/v1/oidc/start and /auth/v1/oidc/callback (ADR-0035) ----

func (s *HTTPServer) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	u, err := s.svc.StartOIDC(r.Context())
	if err != nil {
		oidcError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"authorizationUrl": u})
}

type oidcCallbackRequest struct {
	Code  string `json:"code"`
	State string `json:"state"`
}

func (s *HTTPServer) handleOIDCCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req oidcCallbackRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "the body is not a callback", http.StatusBadRequest)
		return
	}
	token, ttl, err := s.svc.FinishOIDC(r.Context(), req.Code, req.State)
	if err != nil {
		oidcError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{AccessToken: token, ExpiresIn: int(ttl.Seconds())})
}

// oidcError says as little as is useful: why a login is refused stays in this log.
func oidcError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrOIDCOff):
		http.Error(w, "federated login is not configured", http.StatusNotFound)
	case errors.Is(err, application.ErrNoRole):
		log.Printf("authentication: federated login refused: %v", err)
		http.Error(w, "this identity has no OpenBastion role", http.StatusForbidden)
	case errors.Is(err, application.ErrOIDCRejected):
		log.Printf("authentication: federated login refused: %v", err)
		http.Error(w, "the federated login was refused", http.StatusUnauthorized)
	default:
		log.Printf("authentication: federated login failed: %v", err)
		http.Error(w, "the federated login cannot be completed now", http.StatusServiceUnavailable)
	}
}

// -- GET /auth/v1/ldap and POST /auth/v1/ldap/login (ADR-0061) ----

type ldapInfoResponse struct {
	Enabled bool `json:"enabled"`
}

func (s *HTTPServer) handleLDAPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ldapInfoResponse{Enabled: s.svc.DirectoryEnabled()})
}

func (s *HTTPServer) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req loginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "the body is not a login", http.StatusBadRequest)
		return
	}
	token, ttl, err := s.svc.LoginLDAP(r.Context(), req.Username, req.Password)
	if err != nil {
		ldapError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{AccessToken: token, ExpiresIn: int(ttl.Seconds())})
}

// ldapError says as little as is useful: why a login is refused stays in this log, which names
// neither the password nor the login name.
func ldapError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrDirectoryOff):
		http.Error(w, "directory login is not configured", http.StatusNotFound)
	case errors.Is(err, application.ErrNoRole):
		log.Printf("authentication: directory login refused: the user's groups give no OpenBastion role")
		http.Error(w, "this identity has no OpenBastion role", http.StatusForbidden)
	case errors.Is(err, application.ErrDirectoryRejected):
		http.Error(w, "invalid credentials", http.StatusUnauthorized)
	default:
		log.Printf("authentication: directory login failed: %v", err)
		http.Error(w, "the directory cannot be asked now", http.StatusServiceUnavailable)
	}
}

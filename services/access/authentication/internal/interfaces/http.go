// Package interfaces exposes user onboarding, POST /auth/login (doc 05
// §2) and token verification over JSON/HTTP — see
// password-vault/internal/interfaces/http.go for the sandbox network
// note this mirrors.
package interfaces

import (
	"encoding/json"
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

// -- POST /auth/v1/login (mirrors POST /auth/login, doc 05 §2) ---------

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

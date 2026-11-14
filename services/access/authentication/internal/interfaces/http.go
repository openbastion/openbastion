// Package interfaces exposes user onboarding, POST /auth/login (docs/api/rest/openapi.yaml
// §2) and token verification over JSON/HTTP — see
// password-vault/internal/interfaces/http.go for the sandbox network
// note this mirrors.
package interfaces

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
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
	mux.HandleFunc("/auth/v1/oidc", s.handleOIDCInfo)
	mux.HandleFunc("/auth/v1/oidc/start", s.handleOIDCStart)
	mux.HandleFunc("/auth/v1/oidc/callback", s.handleOIDCCallback)
	mux.HandleFunc("/auth/v1/ldap", s.handleLDAPInfo)
	mux.HandleFunc("/auth/v1/ldap/login", s.handleLDAPLogin)
	mux.HandleFunc("/auth/v1/mfa/verify", s.handleMFAVerify)
	mux.HandleFunc("/auth/v1/mfa/enroll", s.handleMFAEnroll)
	mux.HandleFunc("/auth/v1/mfa/enroll/confirm", s.handleMFAConfirm)
	mux.HandleFunc("/auth/v1/mfa/webauthn/verify", s.handleWebAuthnVerify)
	mux.HandleFunc("/auth/v1/mfa/webauthn/enroll/confirm", s.handleWebAuthnConfirm)
	mux.HandleFunc("/auth/v1/mfa/webauthn/keys/add", s.handleWebAuthnAddKey)
	mux.HandleFunc("/auth/v1/mfa/keys", s.handleWebAuthnKeys)
	mux.HandleFunc("/auth/v1/mfa/revoke-key", s.handleWebAuthnRevoke)
	mux.HandleFunc("/auth/v1/mfa/enrollment-codes", s.handleMFAEnrollmentCode)
	mux.HandleFunc("/auth/v1/mfa/reset", s.handleMFAReset)
	mux.HandleFunc("/auth/v1/internal/action-step-up/start", s.handleMFAActionStart)
	mux.HandleFunc("/auth/v1/internal/action-step-up/verify", s.handleMFAActionVerify)
	mux.HandleFunc("/auth/v1/internal/action-step-up/consume", s.handleMFAActionConsume)
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
	if writeMFAChallenge(w, err) {
		return
	}
	if errors.Is(err, application.ErrAuditUnavailable) { // the password was right; the audit is down: 503, no token
		log.Printf("authentication: login not completed: %v", err)
		http.Error(w, "the login cannot be recorded now", http.StatusServiceUnavailable)
		return
	}
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

// -- GET /auth/v1/oidc, POST /auth/v1/oidc/start and /auth/v1/oidc/callback (ADR-0035, ADR-0076) ----

// providersResponse is what the login screen may know of the providers or directories: their ID
// and label, never an issuer, a URL or a base (ADR-0076 §9).
type providersResponse struct {
	Enabled   bool                       `json:"enabled"`
	Providers []application.ProviderInfo `json:"providers"`
}

func (s *HTTPServer) handleOIDCInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	p := s.svc.OIDCProviders()
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(providersResponse{Enabled: len(p) > 0, Providers: p})
}

type oidcStartRequest struct {
	Provider string `json:"provider"`
}

func (s *HTTPServer) handleOIDCStart(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// The body may be empty (one provider): {"provider": "<id>"} otherwise.
	var req oidcStartRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&req); err != nil && !errors.Is(err, io.EOF) {
		http.Error(w, "the body is not a start", http.StatusBadRequest)
		return
	}
	u, err := s.svc.StartOIDC(r.Context(), req.Provider)
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
	case errors.Is(err, application.ErrProviderRequired), errors.Is(err, application.ErrUnknownProvider):
		http.Error(w, err.Error(), http.StatusBadRequest)
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
	Enabled     bool                       `json:"enabled"`
	Directories []application.ProviderInfo `json:"directories"`
}

type ldapLoginRequest struct {
	Directory string `json:"directory"` // ADR-0076: required when several directories are configured
	Username  string `json:"username"`
	Password  string `json:"password"`
}

func (s *HTTPServer) handleLDAPInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(ldapInfoResponse{Enabled: s.svc.DirectoryEnabled(), Directories: s.svc.Directories()})
}

func (s *HTTPServer) handleLDAPLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req ldapLoginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "the body is not a login", http.StatusBadRequest)
		return
	}
	token, ttl, err := s.svc.LoginLDAP(r.Context(), req.Directory, req.Username, req.Password)
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
	if writeMFAChallenge(w, err) {
		return
	}
	switch {
	case errors.Is(err, application.ErrDirectoryOff):
		http.Error(w, "directory login is not configured", http.StatusNotFound)
	case errors.Is(err, application.ErrProviderRequired), errors.Is(err, application.ErrUnknownProvider):
		http.Error(w, err.Error(), http.StatusBadRequest)
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

// -- the second factor (ADR-0062) -------------------------------------------------------

type mfaChallengeResponse struct {
	MFA       string          `json:"mfa"` // "required" or "enrollment_required"
	Challenge string          `json:"challenge"`
	ExpiresIn int             `json:"expiresIn"`
	Factors   []string        `json:"factors"`            // ADR-0065: "totp", "webauthn"
	WebAuthn  json.RawMessage `json:"webauthn,omitempty"` // the assertion options, for navigator.credentials.get
}

// writeMFAChallenge answers a login whose password was right but whose roles require a second
// factor: 401 — a client that does not know the second factor sees a refusal — with the challenge.
func writeMFAChallenge(w http.ResponseWriter, err error) bool {
	var c *application.MFAChallengeRequired
	if !errors.As(err, &c) {
		return false
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(mfaChallengeResponse{MFA: c.Kind, Challenge: c.Challenge, ExpiresIn: int(c.ExpiresIn.Seconds()), Factors: c.Factors, WebAuthn: c.WebAuthn})
	return true
}

type mfaCodeRequest struct {
	Challenge string `json:"challenge"`
	Code      string `json:"code"`
}

type mfaEnrollRequest struct {
	Challenge      string `json:"challenge"`
	EnrollmentCode string `json:"enrollmentCode"`
	Factor         string `json:"factor"` // "totp" (the default) or "webauthn" (ADR-0065)
}

type mfaEnrollResponse struct {
	Secret     string          `json:"secret,omitempty"`
	OTPAuthURI string          `json:"otpauthUri,omitempty"`
	WebAuthn   json.RawMessage `json:"webauthn,omitempty"` // the creation options, for navigator.credentials.create
}

// webauthnRequest is a challenge and the browser's answer, as it sent it.
type webauthnRequest struct {
	Challenge  string          `json:"challenge"`
	Credential json.RawMessage `json:"credential"`
}

func decodePost(w http.ResponseWriter, r *http.Request, into any) bool {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return false
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(into); err != nil {
		http.Error(w, "the body cannot be read", http.StatusBadRequest)
		return false
	}
	return true
}

// mfaError says as little as is useful; no code, challenge or secret is ever logged.
func mfaError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, application.ErrMFAOff):
		http.Error(w, "the second factor is not configured", http.StatusNotFound)
	case errors.Is(err, application.ErrUnknownAccount):
		http.Error(w, "no such account", http.StatusNotFound)
	case errors.Is(err, application.ErrUnknownKey):
		http.Error(w, "no such security key", http.StatusNotFound)
	case errors.Is(err, application.ErrMFARejected):
		http.Error(w, "the second factor was refused", http.StatusUnauthorized)
	default:
		log.Printf("authentication: second factor failed: %v", err)
		http.Error(w, "the second factor cannot be checked now", http.StatusServiceUnavailable)
	}
}

func writeToken(w http.ResponseWriter, token string, ttl time.Duration) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(loginResponse{AccessToken: token, ExpiresIn: int(ttl.Seconds())})
}

func (s *HTTPServer) handleMFAVerify(w http.ResponseWriter, r *http.Request) {
	var req mfaCodeRequest
	if !decodePost(w, r, &req) {
		return
	}
	token, ttl, err := s.svc.VerifyMFA(r.Context(), req.Challenge, req.Code)
	if err != nil {
		mfaError(w, err)
		return
	}
	writeToken(w, token, ttl)
}

func (s *HTTPServer) handleMFAEnroll(w http.ResponseWriter, r *http.Request) {
	var req mfaEnrollRequest
	if !decodePost(w, r, &req) {
		return
	}
	e, err := s.svc.StartEnrollment(r.Context(), req.Challenge, req.EnrollmentCode, req.Factor)
	if err != nil {
		mfaError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(mfaEnrollResponse{Secret: e.Secret, OTPAuthURI: e.OTPAuthURI, WebAuthn: e.WebAuthn})
}

func (s *HTTPServer) handleWebAuthnVerify(w http.ResponseWriter, r *http.Request) {
	var req webauthnRequest
	if !decodePost(w, r, &req) {
		return
	}
	token, ttl, err := s.svc.VerifyWebAuthn(r.Context(), req.Challenge, req.Credential)
	if err != nil {
		mfaError(w, err)
		return
	}
	writeToken(w, token, ttl)
}

func (s *HTTPServer) handleWebAuthnConfirm(w http.ResponseWriter, r *http.Request) {
	var req webauthnRequest
	if !decodePost(w, r, &req) {
		return
	}
	token, ttl, err := s.svc.ConfirmWebAuthnEnrollment(r.Context(), req.Challenge, req.Credential)
	if err != nil {
		mfaError(w, err)
		return
	}
	writeToken(w, token, ttl)
}

func (s *HTTPServer) handleMFAConfirm(w http.ResponseWriter, r *http.Request) {
	var req mfaCodeRequest
	if !decodePost(w, r, &req) {
		return
	}
	token, ttl, err := s.svc.ConfirmEnrollment(r.Context(), req.Challenge, req.Code)
	if err != nil {
		mfaError(w, err)
		return
	}
	writeToken(w, token, ttl)
}

type mfaEnrollmentCodeRequest struct {
	Source    string `json:"source"` // "local" or "ldap"
	LoginName string `json:"loginName"`
}

type mfaEnrollmentCodeResponse struct {
	EnrollmentCode string `json:"enrollmentCode"`
	ExpiresAt      string `json:"expiresAt"`
}

func (s *HTTPServer) handleMFAEnrollmentCode(w http.ResponseWriter, r *http.Request) {
	var req mfaEnrollmentCodeRequest
	if !decodePost(w, r, &req) {
		return
	}
	code, expires, err := s.svc.IssueEnrollmentCode(r.Context(), caller(r), req.Source, req.LoginName)
	if err != nil {
		mfaError(w, err)
		return
	}
	// The administrator's gesture is in this log; the code is not (ADR-0062: not yet in the audit).
	log.Printf("authentication: an MFA enrollment code was issued for %s account %q, valid until %s", req.Source, req.LoginName, expires.UTC().Format(time.RFC3339))
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(mfaEnrollmentCodeResponse{EnrollmentCode: code, ExpiresAt: expires.UTC().Format(time.RFC3339)})
}

type mfaResetRequest struct {
	Username string `json:"username"`
}

func (s *HTTPServer) handleMFAReset(w http.ResponseWriter, r *http.Request) {
	var req mfaResetRequest
	if !decodePost(w, r, &req) {
		return
	}
	if err := s.svc.ResetMFA(r.Context(), caller(r), req.Username); err != nil {
		mfaError(w, err)
		return
	}
	log.Printf("authentication: the second factor of %q was reset", req.Username)
	w.WriteHeader(http.StatusNoContent)
}

// caller is who calls, from its certificate (ADR-0010): the actor of an administrative gesture in
// the audit (ADR-0064). Without internal TLS nobody is verified, and the audit says so.
func caller(r *http.Request) string {
	if c, ok := mtls.CallerFrom(r.Context()); ok && c != "" {
		return c
	}
	return "unverified-caller"
}

// -- one more security key, and the administrator's keys (ADR-0066) ----------------------

type webauthnAddKeyRequest struct {
	Challenge      string          `json:"challenge"`
	Credential     json.RawMessage `json:"credential"`
	EnrollmentCode string          `json:"enrollmentCode"`
}

func (s *HTTPServer) handleWebAuthnAddKey(w http.ResponseWriter, r *http.Request) {
	var req webauthnAddKeyRequest
	if !decodePost(w, r, &req) {
		return
	}
	options, err := s.svc.AddWebAuthnKey(r.Context(), req.Challenge, req.Credential, req.EnrollmentCode)
	if err != nil {
		mfaError(w, err)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(mfaEnrollResponse{WebAuthn: options})
}

type webauthnKeysRequest struct {
	Username string `json:"username"`
}

type webauthnKeyInfo struct {
	KeyID      string `json:"keyId"` // base64url, as revoke-key takes it
	CreatedAt  string `json:"createdAt"`
	LastUsedAt string `json:"lastUsedAt,omitempty"`
}

type webauthnKeysResponse struct {
	Keys []webauthnKeyInfo `json:"keys"`
}

func (s *HTTPServer) handleWebAuthnKeys(w http.ResponseWriter, r *http.Request) {
	var req webauthnKeysRequest
	if !decodePost(w, r, &req) {
		return
	}
	keys, err := s.svc.WebAuthnKeys(r.Context(), req.Username)
	if err != nil {
		mfaError(w, err)
		return
	}
	out := webauthnKeysResponse{Keys: []webauthnKeyInfo{}}
	for _, k := range keys {
		i := webauthnKeyInfo{KeyID: base64.RawURLEncoding.EncodeToString(k.ID), CreatedAt: k.CreatedAt.UTC().Format(time.RFC3339)}
		if !k.LastUsedAt.IsZero() {
			i.LastUsedAt = k.LastUsedAt.UTC().Format(time.RFC3339)
		}
		out.Keys = append(out.Keys, i)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

type webauthnRevokeRequest struct {
	Username string `json:"username"`
	KeyID    string `json:"keyId"`
}

func (s *HTTPServer) handleWebAuthnRevoke(w http.ResponseWriter, r *http.Request) {
	var req webauthnRevokeRequest
	if !decodePost(w, r, &req) {
		return
	}
	id, err := base64.RawURLEncoding.DecodeString(req.KeyID)
	if err != nil || len(id) == 0 {
		http.Error(w, "keyId is the base64url identifier mfa keys gives", http.StatusBadRequest)
		return
	}
	if err := s.svc.RevokeWebAuthnKey(r.Context(), caller(r), req.Username, id); err != nil {
		mfaError(w, err)
		return
	}
	log.Printf("authentication: a security key of %q was revoked", req.Username)
	w.WriteHeader(http.StatusNoContent)
}

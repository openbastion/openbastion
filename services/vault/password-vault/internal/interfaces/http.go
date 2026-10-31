// Package interfaces exposes VaultAuthorization and VaultCredentialIssuance
// (proto/vault/v1/vault.proto) over JSON/HTTP.
//
// SANDBOX NOTE: this project's internal transport is specified as gRPC
// (docs/api/grpc/README.md). google.golang.org/grpc and
// google.golang.org/protobuf could not be fetched in this build sandbox —
// see /NOTES_SANDBOX.md at the repo root for the exact network constraint.
// This HTTP/JSON layer implements the same request/response shapes as the
// .proto messages, field for field, so it can be swapped for generated
// gRPC code later without touching internal/application or internal/domain.
package interfaces

import (
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/application"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

type HTTPServer struct {
	svc *application.VaultService

	// CallerFromCertificate makes the identity of the proxy redeeming a scope
	// the one in its client certificate (ADR-0010), instead of the one it writes
	// in the request. Set when mutual TLS is on. Left unset, the claim in the
	// body is believed — development only, where nothing authenticates anyone.
	CallerFromCertificate bool
}

func NewHTTPServer(svc *application.VaultService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/vault/v1/onboard-account", s.handleOnboardAccount)
	mux.HandleFunc("/vault/v1/rotate", s.handleRotate)
	mux.HandleFunc("/vault/v1/rotate-after-use", s.handleRotateAfterUse)
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

// -- onboard-account (mirrors POST /vault/accounts, docs/api/rest/openapi.yaml) -------------

type onboardAccountRequest struct {
	ID             string   `json:"id"`
	Name           string   `json:"name"`
	Username       string   `json:"username"`
	TargetHost     string   `json:"targetHost"`
	Protocol       string   `json:"protocol"`
	RotationPolicy string   `json:"rotationPolicy"`
	InitialSecret  []byte   `json:"initialSecret"`
	ActorRoles     []string `json:"actorRoles"`

	// ReconciliationAccountID: the account of the same target that can change this one's
	// password (ADR-0037); empty — the account cannot be rotated.
	ReconciliationAccountID string `json:"reconciliationAccountId"`
	// HostKey is the target's SSH host key, required (ADR-0039).
	HostKey string `json:"hostKey"`
	// RotationIntervalDays: required for rotationPolicy "scheduled", refused otherwise (ADR-0040).
	RotationIntervalDays int `json:"rotationIntervalDays"`
}

func (s *HTTPServer) handleOnboardAccount(w http.ResponseWriter, r *http.Request) {
	var req onboardAccountRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err := s.svc.OnboardPinned(r.Context(), req.ActorRoles, application.OnboardInput{ID: req.ID, Name: req.Name, Username: req.Username,
		TargetHost: req.TargetHost, Protocol: req.Protocol, Policy: domain.RotationPolicy(req.RotationPolicy), InitialSecret: req.InitialSecret,
		ReconciliationAccountID: req.ReconciliationAccountID, HostKey: req.HostKey, RotationIntervalDays: req.RotationIntervalDays})
	if err != nil {
		writeAdminError(w, "onboarding account "+req.ID, err)
		return
	}
	w.WriteHeader(http.StatusCreated)
}

// -- rotate (mirrors POST /vault/accounts/{id}/rotate, docs/api/rest/openapi.yaml) ---------

type rotateRequest struct {
	AccountID  string   `json:"accountId"`
	NewSecret  []byte   `json:"newSecret"`
	ActorRoles []string `json:"actorRoles"`
	// ActorID is who asked, as the Gateway verified it: the actor of the audit events.
	ActorID string `json:"actorId"`
}

func (s *HTTPServer) handleRotate(w http.ResponseWriter, r *http.Request) {
	var req rotateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := s.svc.RotateAs(r.Context(), req.ActorID, req.ActorRoles, req.AccountID, req.NewSecret); err != nil {
		writeAdminError(w, "rotating account "+req.AccountID, err)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}

// -- rotate-after-use: a session on the account ended (ADR-0037), from the Broker ----

type rotateAfterUseRequest struct {
	AccountID string `json:"accountId"`
	SessionID string `json:"sessionId"`
	// EndedAt is when the session ended (ADR-0044): an account rotated since owes nothing, so a
	// repeated notice is harmless. Absent (an older Broker): now.
	EndedAt *time.Time `json:"endedAt"`
}

// handleRotateAfterUse answers 200 once the rotation owed is RECORDED — paid or not, the Vault
// sees it through (ADR-0044); 404 for an account it does not have (nothing is owed); 503 if it
// could not even record it, for the Broker to tell it again.
func (s *HTTPServer) handleRotateAfterUse(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req rotateAfterUseRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4096)).Decode(&req); err != nil || req.AccountID == "" {
		http.Error(w, "the body is not a rotate-after-use request", http.StatusBadRequest)
		return
	}
	endedAt := time.Now()
	if req.EndedAt != nil {
		endedAt = *req.EndedAt
	}
	res, err := s.svc.RotateAfterUse(r.Context(), req.AccountID, endedAt)
	if errors.Is(err, domain.ErrNotFound) {
		http.Error(w, "account not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("password-vault: the rotation after session %s of account %s could not be recorded: %v", req.SessionID, req.AccountID, err)
		http.Error(w, "the rotation after use could not be recorded, tell it again", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]bool{"owed": res.Owed, "rotated": res.Rotated})
}

// writeAdminError answers a failed administrative operation (ADR-0043): a refusal with its own
// reason, a failure of a dependency — Authorization, a store — with a generic 503 and its
// cause in this log. What a client reads never carries a dependency's text.
func writeAdminError(w http.ResponseWriter, what string, err error) {
	status := adminErrorStatus(err)
	var msg string
	switch {
	case errors.Is(err, domain.ErrNotFound):
		msg = "account not found"
	case errors.Is(err, domain.ErrAlreadyExists):
		msg = domain.ErrAlreadyExists.Error()
	case errors.Is(err, application.ErrAuditUnavailable):
		msg = application.ErrAuditUnavailable.Error()
	case errors.Is(err, application.ErrAccessDenied),
		errors.Is(err, application.ErrBadHostKey), errors.Is(err, application.ErrBadRotationInterval),
		errors.Is(err, application.ErrNoReconciliation), errors.Is(err, application.ErrNoHostKey),
		errors.Is(err, domain.ErrRotationInProgress), errors.Is(err, application.ErrRotationOff),
		// What the target answered: an administrator configured it, and needs it to act.
		errors.Is(err, application.ErrRotationRefused), errors.Is(err, application.ErrRotationUnverified):
		msg = err.Error()
	default:
		status, msg = http.StatusServiceUnavailable, "a dependency of the Vault is unavailable: nothing was changed, try again shortly"
	}
	if status >= 500 {
		log.Printf("password-vault: %s: %v", what, err)
	}
	http.Error(w, msg, status)
}

// adminErrorStatus maps a failed account-admin operation (rotate, delete)
// onto an HTTP status: domain.ErrNotFound — unknown OR disabled account, which
// the Vault deliberately does not distinguish — is 404; everything else
// (RBAC denial, Authorization unreachable and therefore fail-closed) stays
// 403, exactly as before. The RBAC check runs before the existence check in
// VaultService, so an unauthorized caller always gets 403 whether or not the
// account exists: the 404 cannot be used to probe which accounts exist.
func adminErrorStatus(err error) int {
	switch {
	case errors.Is(err, domain.ErrNotFound):
		return http.StatusNotFound
	case errors.Is(err, application.ErrNoReconciliation), errors.Is(err, domain.ErrRotationInProgress), errors.Is(err, application.ErrNoHostKey):
		return http.StatusConflict
	case errors.Is(err, application.ErrRotationRefused), errors.Is(err, application.ErrRotationUnverified):
		return http.StatusBadGateway
	case errors.Is(err, application.ErrRotationOff):
		return http.StatusNotImplemented
	case errors.Is(err, application.ErrAuditUnavailable):
		return http.StatusServiceUnavailable
	case errors.Is(err, domain.ErrAlreadyExists):
		return http.StatusConflict
	case errors.Is(err, application.ErrBadHostKey), errors.Is(err, application.ErrBadRotationInterval):
		return http.StatusBadRequest
	case errors.Is(err, application.ErrAccessDenied):
		return http.StatusForbidden
	}
	return http.StatusServiceUnavailable
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
		// The refusal says its reason by a stable code (ADR-0042): the Broker tells the operator
		// what to do from the code, never from this text.
		if errors.Is(err, application.ErrNoHostKey) {
			writeRefusal(w, http.StatusConflict, RefusalNoPinnedHostKey, err.Error()) // pin it first (ADR-0039)
			return
		}
		writeRefusal(w, http.StatusForbidden, RefusalRefused, err.Error())
		return
	}
	writeJSON(w, authorizeScopeResponse{ScopeToken: token, ExpiresAt: expiresAt})
}

// -- fetch-credential (VaultCredentialIssuance.FetchCredential) ------------
//
// The single endpoint in the whole system that returns secret material —
// ADR-0003. Called only by a proxy, never by the control plane.

type fetchCredentialRequest struct {
	ScopeToken string `json:"scope_token"`
	// CallingProxyID is a claim. With CallerFromCertificate it is optional, and
	// refused if it disagrees with the certificate; without, it is all there is.
	CallingProxyID string `json:"calling_proxy_id"`
}

type fetchCredentialResponse struct {
	CredentialType     string `json:"credential_type"`
	CredentialMaterial []byte `json:"credential_material"`
	// The target the secret is for (ADR-0039): its address and its pinned host key.
	TargetHost string `json:"target_host"`
	HostKey    string `json:"host_key"`
}

func (s *HTTPServer) handleFetchCredential(w http.ResponseWriter, r *http.Request) {
	var req fetchCredentialRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	callingProxy := req.CallingProxyID
	if s.CallerFromCertificate {
		// Who is redeeming this scope is a fact the transport established, not a
		// sentence in the request: holding a scope token is not enough to pass
		// for the proxy it was issued to.
		id, ok := mtls.CallerFrom(r.Context())
		if !ok {
			http.Error(w, "caller identity required", http.StatusUnauthorized)
			return
		}
		if req.CallingProxyID != "" && req.CallingProxyID != id {
			http.Error(w, "claimed identity does not match the client certificate", http.StatusForbidden)
			return
		}
		callingProxy = id
	}
	d, err := s.svc.FetchCredential(r.Context(), req.ScopeToken, callingProxy)
	if err != nil {
		status := http.StatusForbidden
		if errors.Is(err, application.ErrNoHostKey) {
			status = http.StatusConflict
		}
		http.Error(w, err.Error(), status)
		return
	}
	writeJSON(w, fetchCredentialResponse{CredentialType: d.Type, CredentialMaterial: d.Material, TargetHost: d.TargetHost, HostKey: d.HostKey})
}

// -- GET /vault/v1/accounts/{id}, DELETE /vault/v1/accounts/{id} -----------
// (mirrors GET and DELETE /vault/accounts/{id}, docs/api/rest/openapi.yaml)
//
// Metadata only — target host, username, protocol — never a secret, not
// even encrypted. GET is what the Session Broker calls to resolve where
// and as whom to connect, before ever touching the Vault's scope/credential
// endpoints; it returns 404 for a disabled account exactly as for an
// unknown one (application.VaultService.GetAccount), which is what makes
// DELETE below actually block new sessions against the account it disabled.

type accountResponse struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Username       string     `json:"username"`
	TargetHost     string     `json:"targetHost"`
	Protocol       string     `json:"protocol"`
	RotationPolicy string     `json:"rotationPolicy"`
	LastRotatedAt  *time.Time `json:"lastRotatedAt,omitempty"`
	CreatedAt      time.Time  `json:"createdAt"`
	DisabledAt     *time.Time `json:"disabledAt,omitempty"`
	// The pinned host key of the target and its fingerprint (ADR-0039); empty: not pinned.
	HostKey            string `json:"hostKey"`
	HostKeyFingerprint string `json:"hostKeyFingerprint"`
	// RotationIntervalDays and NextRotationAt: a scheduled account's cadence and next due
	// time (ADR-0040); absent for any other.
	RotationIntervalDays int        `json:"rotationIntervalDays,omitempty"`
	NextRotationAt       *time.Time `json:"nextRotationAt,omitempty"`
	// RotationFailures: scheduled rotations failed in a row (ADR-0041); absent at 0.
	RotationFailures int `json:"rotationFailures,omitempty"`
	// RotationOwedSince: a session ended and left a rotation owed (ADR-0044); absent: none.
	RotationOwedSince *time.Time `json:"rotationOwedSince,omitempty"`
}

// toAccountResponse is the single place that maps domain.PrivilegedAccount
// onto the wire shape — used by both handleAccountItem's GET branch and
// handleListAccounts, so the two can never drift out of sync the way
// rotationPolicy/lastRotatedAt/createdAt had, undetected, until this
// increment (see NOTES_SANDBOX.md: docs/api/rest/openapi.yaml's PrivilegedAccount schema
// documented all three from the start; this HTTP layer never populated
// them).
func toAccountResponse(a *domain.PrivilegedAccount) accountResponse {
	return accountResponse{
		ID: a.ID, Name: a.Name, Username: a.Username,
		TargetHost: a.TargetHost, Protocol: a.Protocol, RotationPolicy: string(a.RotationPolicy),
		LastRotatedAt: a.LastRotatedAt, CreatedAt: a.CreatedAt, DisabledAt: a.DisabledAt,
		HostKey: a.HostKey, HostKeyFingerprint: application.HostKeyFingerprint(a.HostKey),
		RotationIntervalDays: a.RotationIntervalDays, NextRotationAt: a.RotationDueAt(), RotationFailures: a.RotationFailures, RotationOwedSince: a.RotationOwedSince,
	}
}

func (s *HTTPServer) handleAccountItem(w http.ResponseWriter, r *http.Request) {
	id := r.URL.Path[len("/vault/v1/accounts/"):]
	if id == "" {
		http.Error(w, "missing account id", http.StatusBadRequest)
		return
	}
	if accountID, ok := strings.CutSuffix(id, "/host-key"); ok {
		s.handleSetHostKey(w, r, accountID)
		return
	}

	switch r.Method {
	case http.MethodGet:
		account, err := s.svc.GetAccount(r.Context(), id)
		if err != nil {
			writeAdminError(w, "reading account "+id, err)
			return
		}
		writeJSON(w, toAccountResponse(account))

	case http.MethodDelete:
		// actorRoles travels in the query string, not a JSON body — a
		// DELETE conventionally carries none, unlike onboard/rotate's
		// POST bodies. The Gateway builds this same query parameter
		// (api-gateway/internal/interfaces/http.go).
		actorRoles := splitCommaList(r.URL.Query().Get("actorRoles"))
		if err := s.svc.DisableAccount(r.Context(), actorRoles, id); err != nil {
			writeAdminError(w, "disabling account "+id, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// -- GET /vault/v1/accounts (mirrors GET /vault/accounts, docs/api/rest/openapi.yaml) -------

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
		writeAdminError(w, "listing accounts", err)
		return
	}

	// Report the page that was SERVED (same rule ListAccounts applied), not
	// the one requested: a request with no parameters is page 1, size 20.
	page, pageSize = application.ClampPage(page, pageSize)

	items := make([]accountResponse, 0, len(accounts))
	for _, a := range accounts {
		items = append(items, toAccountResponse(a))
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

// -- PUT /vault/v1/accounts/{id}/host-key (ADR-0039), from the Gateway ---------

type setHostKeyRequest struct {
	HostKey    string   `json:"hostKey"`
	ActorRoles []string `json:"actorRoles"`
	ActorID    string   `json:"actorId"`
}

func (s *HTTPServer) handleSetHostKey(w http.ResponseWriter, r *http.Request, accountID string) {
	if r.Method != http.MethodPut {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req setHostKeyRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&req); err != nil {
		http.Error(w, "the body is not a host key", http.StatusBadRequest)
		return
	}
	fp, err := s.svc.SetHostKey(r.Context(), req.ActorID, req.ActorRoles, accountID, req.HostKey)
	if err != nil {
		writeAdminError(w, "pinning the host key of account "+accountID, err)
		return
	}
	writeJSON(w, map[string]string{"hostKeyFingerprint": fp})
}

// Refusal codes of authorize-scope (ADR-0042): the contract a caller reads.
const (
	RefusalNoPinnedHostKey = "no_pinned_host_key"
	RefusalRefused         = "refused"
)

// writeRefusal answers status with {"code": code, "error": message}.
func writeRefusal(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"code": code, "error": message})
}

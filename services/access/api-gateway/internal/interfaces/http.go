// Package interfaces implements the API Gateway's HTTP surface — the
// single public entry point (doc 00 §4.1) in front of Authentication,
// Session Broker, Password Vault, and Authorization.
//
// Every route requires a valid bearer token except /auth/login. Password
// Vault enforces real RBAC on its own write operations (onboarding,
// rotation) via Authorization.CheckAccess, and Authorization enforces the
// same discipline on itself for POST /policies (authz:policy-admin) — the
// Gateway's job in both cases is only to inject the caller's verified
// roles, never to duplicate that decision; see /NOTES_SANDBOX.md for why
// the check belongs in the service itself rather than (or in addition
// to) the Gateway: a client reaching Password Vault or Authorization
// directly, bypassing the Gateway, must be exactly as gated as one going
// through it.
package interfaces

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	neturl "net/url"
	"strings"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
)

type GatewayServer struct {
	authClient        application.TokenVerifier
	requestLimiter    *application.RateLimiter
	loginLimiter      *application.RateLimiter
	authenticationURL string
	sessionBrokerURL  string
	vaultURL          string
	authorizationURL  string
	// commandRecorderURL is where GET /sessions/{id}/recording is routed.
	commandRecorderURL string
	httpClient         *http.Client
}

func NewGatewayServer(authClient application.TokenVerifier, requestLimiter, loginLimiter *application.RateLimiter, authenticationURL, sessionBrokerURL, vaultURL, authorizationURL, commandRecorderURL string) *GatewayServer {
	return &GatewayServer{
		authClient: authClient, requestLimiter: requestLimiter, loginLimiter: loginLimiter,
		authenticationURL: authenticationURL, sessionBrokerURL: sessionBrokerURL,
		vaultURL: vaultURL, authorizationURL: authorizationURL, commandRecorderURL: commandRecorderURL,
		httpClient: http.DefaultClient,
	}
}

// WithHTTPClient sets the client the Gateway uses to reach its upstreams. Under
// INTERNAL_TLS it is the mutual-TLS client that knows every upstream by identity
// (ADR-0010); by default it is http.DefaultClient.
func (g *GatewayServer) WithHTTPClient(c *http.Client) *GatewayServer {
	g.httpClient = c
	return g
}

func (g *GatewayServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", g.handleLogin) // public
	mux.HandleFunc("/sessions", g.requireAuth(g.handleSessionsCollection))
	mux.HandleFunc("/sessions/", g.requireAuth(g.handleSessionItem))
	mux.HandleFunc("/vault/accounts", g.requireAuth(g.handleVaultAccountsCollection))
	mux.HandleFunc("/vault/accounts/", g.requireAuth(g.handleVaultAccountItem))
	mux.HandleFunc("/policies", g.requireAuth(g.handlePoliciesCollection))
	mux.HandleFunc("/healthz", g.handleHealthz)
	return mux
}

func (g *GatewayServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- POST /auth/login (public, mirrors doc 05 §2) ------------------------

func (g *GatewayServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Rate limited by IP, independently of the authenticated-request
	// limiter below — brute-force protection on the login endpoint
	// specifically (Guide Sécurité §4), since it's the one endpoint an
	// unauthenticated attacker can hammer at all.
	if !g.loginLimiter.Allow(clientIP(r)) {
		w.Header().Set("Retry-After", "1")
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.authenticationURL+"/auth/v1/login", r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// -- auth middleware -------------------------------------------------------

// identity is the Gateway's own verified view of the caller — resolved
// exclusively from AuthClient.VerifyToken, never from anything the
// client's request body claims about itself.
type identity struct {
	UserID   string
	Username string
	Roles    []string
}

func (g *GatewayServer) requireAuth(next func(w http.ResponseWriter, r *http.Request, id identity)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !g.requestLimiter.Allow(clientIP(r)) {
			w.Header().Set("Retry-After", "1")
			http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
			return
		}

		authHeader := r.Header.Get("Authorization")
		token, ok := strings.CutPrefix(authHeader, "Bearer ")
		if !ok || token == "" {
			http.Error(w, "missing bearer token", http.StatusUnauthorized)
			return
		}

		userID, username, roles, err := g.authClient.VerifyToken(r.Context(), token)
		if err != nil {
			http.Error(w, "invalid or expired token", http.StatusUnauthorized)
			return
		}

		next(w, r, identity{UserID: userID, Username: username, Roles: roles})
	}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// -- shared forwarding helpers ---------------------------------------------

// forwardJSON marshals body itself, letting a handler rewrite fields
// (identity injection) before anything is sent downstream.
func (g *GatewayServer) forwardJSON(w http.ResponseWriter, ctx context.Context, method, url string, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(encoded))
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	g.doAndRelay(w, req)
}

// forwardPassthrough relays a request's method/body as-is to url — used
// where there is nothing for the Gateway to inject, only a valid token to
// have required to reach this far.
func (g *GatewayServer) forwardPassthrough(w http.ResponseWriter, r *http.Request, method, url string) {
	req, err := http.NewRequestWithContext(r.Context(), method, url, r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	g.doAndRelay(w, req)
}

func (g *GatewayServer) doAndRelay(w http.ResponseWriter, req *http.Request) {
	resp, err := g.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// -- POST /sessions — the identity-injection case -------------------------

func (g *GatewayServer) handleSessionsCollection(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The whole point of doing this at the Gateway: whatever the client
	// put in these two fields is discarded and replaced with the
	// Gateway's own verified identity (doc 00 §4.1, "injection de
	// contexte d'identité"). A client cannot request a session on behalf
	// of another user or grant itself extra roles by editing its request
	// body — see http_test.go's
	// TestHandleSessionsCollection_InjectsVerifiedIdentityOverridingClientClaims.
	body["requestedBy"] = id.UserID
	body["actorRoles"] = id.Roles

	g.forwardJSON(w, r.Context(), http.MethodPost, g.sessionBrokerURL+"/sessions", body)
}

// -- GET/DELETE /sessions/{id}, POST /sessions/{id}/connect ---------------
//
// Pure passthrough to the Session Broker — which itself does not yet check
// session ownership against the caller (a scope this increment did not
// extend; see /NOTES_SANDBOX.md), so there is nothing for the Gateway to
// inject here beyond having already required a valid token to reach this
// far. The one exception is GET /sessions/{id}/recording below, which is
// not the Broker's at all.

func (g *GatewayServer) handleSessionItem(w http.ResponseWriter, r *http.Request, id identity) {
	if sessionID, ok := recordingSessionID(r.URL.Path); ok {
		g.handleSessionRecording(w, r, id, sessionID)
		return
	}
	g.forwardPassthrough(w, r, r.Method, g.sessionBrokerURL+r.URL.Path)
}

// recordingSessionID recognizes /sessions/{id}/recording and returns the id.
func recordingSessionID(path string) (string, bool) {
	rest := strings.TrimPrefix(path, "/sessions/")
	sessionID, ok := strings.CutSuffix(rest, "/recording")
	if !ok || sessionID == "" || strings.Contains(sessionID, "/") {
		return "", false
	}
	return sessionID, true
}

// -- GET /sessions/{id}/recording (doc 05) ---------------------------------
//
// The text recording of a session, served by the Command Recorder. The
// Gateway's part is the same as for the Vault's admin routes: it replaces
// whatever roles the client may have sent with the verified ones, and the
// access decision itself (recording:session:read, RBAC) is the Recorder's.
// Only page and pageSize are taken from the client's query — nothing else
// reaches the Recorder, so a client-supplied actorRoles cannot either.

func (g *GatewayServer) handleSessionRecording(w http.ResponseWriter, r *http.Request, id identity, sessionID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := neturl.Values{}
	for _, key := range []string{"page", "pageSize"} {
		if v := r.URL.Query().Get(key); v != "" {
			q.Set(key, v)
		}
	}
	q.Set("actorRoles", strings.Join(id.Roles, ","))
	g.forwardPassthrough(w, r, http.MethodGet,
		g.commandRecorderURL+"/recorder/v1/sessions/"+neturl.PathEscape(sessionID)+"/commands?"+q.Encode())
}

// -- GET/POST /vault/accounts (mirrors doc 05 §2) --------------------------
//
// GET lists accounts; POST onboards one. Neither has (yet) been seen
// enforcing the caller's role at this layer beyond requireAuth — real
// RBAC is Password Vault's own job (CheckAccess against
// "vault:account-admin:*"), consistent with the package doc comment: the
// Gateway's role here is identity injection, not the access decision
// itself.

func (g *GatewayServer) handleVaultAccountsCollection(w http.ResponseWriter, r *http.Request, id identity) {
	switch r.Method {
	case http.MethodGet:
		// List — page/pageSize pass through from the client's own query
		// string unchanged; actorRoles is appended here since a GET
		// carries no body for the Gateway to inject identity into (the
		// same reasoning, and the same query-string mechanism, as the
		// DELETE branch of handleVaultAccountItem below).
		q := r.URL.Query()
		q.Set("actorRoles", strings.Join(id.Roles, ","))
		g.forwardPassthrough(w, r, http.MethodGet, g.vaultURL+"/vault/v1/accounts?"+q.Encode())

	case http.MethodPost:
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		body["actorRoles"] = id.Roles
		g.forwardJSON(w, r.Context(), http.MethodPost, g.vaultURL+"/vault/v1/onboard-account", body)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// -- GET/DELETE /vault/accounts/{id}, POST /vault/accounts/{id}/rotate ----
//
// This is the one route in this increment that translates doc 05's
// public REST shape into Password Vault's actual internal contract
// rather than passing the path straight through: doc 05 puts the account
// id in the URL for rotate; Password Vault's /vault/v1/rotate expects it
// in the JSON body instead (it predates this routing work). The Gateway
// bridges that here rather than changing Password Vault's already-tested
// internal contract to match a REST shape that was never exercised
// end-to-end until now.

func (g *GatewayServer) handleVaultAccountItem(w http.ResponseWriter, r *http.Request, id identity) {
	rest := strings.TrimPrefix(r.URL.Path, "/vault/accounts/")

	if accountID, ok := strings.CutSuffix(rest, "/rotate"); ok {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// No secret is forwarded — Password Vault auto-generates one when
		// none is supplied (application.VaultService.Rotate), which is
		// the whole point of this endpoint taking no request body in
		// doc 05: an operator triggers rotation, never invents the value.
		g.forwardJSON(w, r.Context(), http.MethodPost, g.vaultURL+"/vault/v1/rotate", map[string]any{
			"accountId": accountID, "actorRoles": id.Roles,
		})
		return
	}

	switch r.Method {
	case http.MethodGet:
		g.forwardPassthrough(w, r, http.MethodGet, g.vaultURL+"/vault/v1/accounts/"+rest)

	case http.MethodDelete:
		// Same query-string identity injection as the GET-list branch of
		// handleVaultAccountsCollection — DELETE carries no body either.
		q := make(neturl.Values)
		q.Set("actorRoles", strings.Join(id.Roles, ","))
		g.forwardPassthrough(w, r, http.MethodDelete, g.vaultURL+"/vault/v1/accounts/"+rest+"?"+q.Encode())

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// -- POST /policies — identity injection on createdBy ----------------------

func (g *GatewayServer) handlePoliciesCollection(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Same principle as session creation (doc 00 §4.1): who created a
	// policy is an audit-relevant fact, and it comes from the Gateway's
	// verified identity, never from what the client's own request body
	// claims. actorRoles is the same identity injection already applied
	// to vault account onboarding/rotation (handleVaultAccountsCollection
	// below) — Authorization now RBAC-gates CreatePolicy itself
	// (authz:policy-admin), so the Gateway must stop any caller from
	// claiming a role it doesn't actually hold here too.
	body["createdBy"] = id.Username
	body["actorRoles"] = id.Roles

	g.forwardJSON(w, r.Context(), http.MethodPost, g.authorizationURL+"/authz/v1/policies", body)
}

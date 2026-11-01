// Package interfaces implements the API Gateway's HTTP surface — the
// single public entry point (docs/architecture/system-overview.md) in front of Authentication,
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
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
)

type GatewayServer struct {
	authClient     application.TokenVerifier
	requestLimiter *application.RateLimiter
	loginLimiter   *application.RateLimiter
	ui             http.Handler
	// sessionLimiter is the per-user budget of POST /sessions (ADR-0014). It is
	// never nil: a Gateway built by hand has the strict default.
	sessionLimiter *application.RateLimiter
	// actionLimiter is the per-user budget of approve, reject, connect and terminate, the
	// session actions that write on every call (ADR-0016, ADR-0017). Never nil either.
	actionLimiter *application.RateLimiter
	// proxyTrust says whose X-Forwarded-For is believed when the per-address limiters
	// look for the client (ADR-0015). It is never nil: a Gateway built by hand trusts
	// nobody, and keys on the address of the peer.
	proxyTrust        *application.ProxyTrust
	authenticationURL string
	sessionBrokerURL  string
	vaultURL          string
	authorizationURL  string
	// commandRecorderURL is where GET /sessions/{id}/recording is routed.
	commandRecorderURL string
	httpClient         *http.Client
	// ldapInfo remembers, a short while, whether directory login is on (ADR-0061).
	ldapInfo ldapInfoCache
}

func NewGatewayServer(authClient application.TokenVerifier, requestLimiter, loginLimiter *application.RateLimiter, authenticationURL, sessionBrokerURL, vaultURL, authorizationURL, commandRecorderURL string) *GatewayServer {
	return &GatewayServer{
		authClient: authClient, requestLimiter: requestLimiter, loginLimiter: loginLimiter,
		sessionLimiter:    application.NewSessionRequestLimiter(0, 0),
		actionLimiter:     application.NewSessionActionLimiter(0, 0),
		proxyTrust:        &application.ProxyTrust{},
		authenticationURL: authenticationURL, sessionBrokerURL: sessionBrokerURL,
		vaultURL: vaultURL, authorizationURL: authorizationURL, commandRecorderURL: commandRecorderURL,
		httpClient: http.DefaultClient,
	}
}

// WithSessionRequestLimiter sets the per-user budget of POST /sessions (ADR-0014).
// A nil limiter keeps the default; there is no way to switch the limit off.
func (g *GatewayServer) WithSessionRequestLimiter(l *application.RateLimiter) *GatewayServer {
	if l != nil {
		g.sessionLimiter = l
	}
	return g
}

// WithSessionActionLimiter sets the per-user budget of approve, reject, connect and
// terminate (ADR-0016, ADR-0017). A nil limiter keeps the default; there is no way to switch the limit off.
func (g *GatewayServer) WithSessionActionLimiter(l *application.RateLimiter) *GatewayServer {
	if l != nil {
		g.actionLimiter = l
	}
	return g
}

// WithProxyTrust declares which peers are reverse proxies whose X-Forwarded-For is
// believed (ADR-0015). A nil value keeps the default, which trusts nobody.
func (g *GatewayServer) WithProxyTrust(t *application.ProxyTrust) *GatewayServer {
	if t != nil {
		g.proxyTrust = t
	}
	return g
}

// WithUI serves the Admin UI under /ui/ (ADR-0036); nil serves nothing there.
func (g *GatewayServer) WithUI(h http.Handler) *GatewayServer {
	g.ui = h
	return g
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
	// Federated login (ADR-0035), public and in the login budget.
	mux.HandleFunc("/auth/oidc/start", g.handleOIDC("/auth/v1/oidc/start"))
	mux.HandleFunc("/auth/oidc/callback", g.handleOIDC("/auth/v1/oidc/callback"))
	// Directory login (ADR-0061): the login is public and in the login budget; whether it is on,
	// public, answered from a short cache.
	mux.HandleFunc("/auth/ldap/login", g.handleLDAPLogin)
	mux.HandleFunc("/auth/ldap", g.handleLDAPInfo)
	// The second factor (ADR-0062): each step is public and in the login budget.
	mux.HandleFunc("/auth/mfa/verify", g.handleMFA("/auth/v1/mfa/verify", "challenge", "code"))
	mux.HandleFunc("/auth/mfa/enroll", g.handleMFA("/auth/v1/mfa/enroll", "challenge", "enrollmentCode", "factor"))
	mux.HandleFunc("/auth/mfa/enroll/confirm", g.handleMFA("/auth/v1/mfa/enroll/confirm", "challenge", "code"))
	// WebAuthn (ADR-0065): the browser's answer is an object, forwarded as it is, bounded.
	mux.HandleFunc("/auth/mfa/webauthn/verify", g.handleMFA("/auth/v1/mfa/webauthn/verify", "challenge", "{credential}"))
	mux.HandleFunc("/auth/mfa/webauthn/enroll/confirm", g.handleMFA("/auth/v1/mfa/webauthn/enroll/confirm", "challenge", "{credential}"))
	mux.HandleFunc("/sessions", g.requireAuth(g.handleSessionsCollection))
	mux.HandleFunc("/sessions/", g.requireAuth(g.handleSessionItem))
	mux.HandleFunc("/vault/accounts", g.requireAuth(g.handleVaultAccountsCollection))
	mux.HandleFunc("/vault/accounts/", g.requireAuth(g.handleVaultAccountItem))
	mux.HandleFunc("/policies", g.requireAuth(g.handlePoliciesCollection))
	mux.HandleFunc("/healthz", g.handleHealthz)
	if g.ui != nil {
		mux.Handle("/ui/", g.ui) // the Admin UI, same origin (ADR-0036)
	}
	return mux
}

func (g *GatewayServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- POST /auth/login (public, mirrors docs/api/rest/openapi.yaml) ------------------------

func (g *GatewayServer) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Rate limited by IP, independently of the authenticated-request
	// limiter below — brute-force protection on the login endpoint
	// specifically (docs/security/authentication.md), since it's the one endpoint an
	// unauthenticated attacker can hammer at all.
	if d := g.loginLimiter.Take(g.clientKey(r)); !d.Allowed {
		w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSeconds()))
		http.Error(w, "too many login attempts", http.StatusTooManyRequests)
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.authenticationURL+"/auth/v1/login", r.Body)
	if err != nil {
		internalError(w, err)
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

// -- POST /auth/oidc/start, /auth/oidc/callback (public, ADR-0035) -------

// handleOIDC forwards one end of a federated login to the Authentication Service. Each call
// takes from the same per-address budget as a password login: both are what an attacker who
// holds nothing can hammer. Only code and state are forwarded, rebuilt, never the raw body.
func (g *GatewayServer) handleOIDC(upstream string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if d := g.loginLimiter.Take(g.clientKey(r)); !d.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSeconds()))
			http.Error(w, "too many login attempts", http.StatusTooManyRequests)
			return
		}
		body := []byte("{}")
		if strings.HasSuffix(upstream, "/callback") {
			var in struct {
				Code  string `json:"code"`
				State string `json:"state"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&in); err != nil {
				http.Error(w, "the body is not a callback", http.StatusBadRequest)
				return
			}
			body, _ = json.Marshal(in)
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, g.authenticationURL+upstream, bytes.NewReader(body))
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := g.httpClient.Do(req)
		if err != nil {
			http.Error(w, "upstream unavailable", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		w.Header().Set("Content-Type", resp.Header.Get("Content-Type"))
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, io.LimitReader(resp.Body, 64<<10))
	}
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
		if d := g.requestLimiter.Take(g.clientKey(r)); !d.Allowed {
			w.Header().Set("Retry-After", strconv.Itoa(d.RetryAfterSeconds()))
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

// clientKey is what the per-address limiters call the client: the address of the peer,
// or — when that peer is a declared reverse proxy — the first address on its
// X-Forwarded-For chain that is not one (ADR-0015). It is never anything a client was
// free to choose.
func (g *GatewayServer) clientKey(r *http.Request) string {
	return g.proxyTrust.ClientKey(r.RemoteAddr, r.Header.Values("X-Forwarded-For"))
}

// -- shared forwarding helpers ---------------------------------------------

// forwardJSON marshals body itself, letting a handler rewrite fields
// (identity injection) before anything is sent downstream.
func (g *GatewayServer) forwardJSON(w http.ResponseWriter, ctx context.Context, method, url string, body any) {
	encoded, err := json.Marshal(body)
	if err != nil {
		internalError(w, err)
		return
	}
	req, err := http.NewRequestWithContext(ctx, method, url, bytes.NewReader(encoded))
	if err != nil {
		internalError(w, err)
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
		internalError(w, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	g.doAndRelay(w, req)
}

// internalError answers an error of the Gateway's own (ADR-0043): a request it could not
// build — its message names the internal URL, which may hold what the client put in its path.
// The client reads a generic 500; the cause stays in this log.
func internalError(w http.ResponseWriter, err error) {
	log.Printf("api-gateway: internal error: %v", err)
	http.Error(w, "internal error", http.StatusInternalServerError)
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

// admitSessionRequest charges one request to the budget of the user the token
// proves — not to the address it came from (behind the reverse proxy that is the
// same for everybody), and not to anything the body says. A request is counted
// whatever happens to it next: it is the attempts that cost the Broker a row and an
// audit event, not the successes (ADR-0014).
func (g *GatewayServer) admitSessionRequest(w http.ResponseWriter, id identity) bool {
	return admitFromBudget(w, id, g.sessionLimiter, "session requests")
}

// admitSessionAction is the same charge for approve, reject, connect (ADR-0016) and
// terminate (ADR-0017), to a budget of its own: it is one bucket for the four, so that
// changing route is not a way to a new budget, and it is not the bucket of POST /sessions.
func (g *GatewayServer) admitSessionAction(w http.ResponseWriter, id identity) bool {
	return admitFromBudget(w, id, g.actionLimiter, "session actions")
}

// admitFromBudget takes one token of the user's bucket. What it says when it
// refuses names the budget (`what`), so that a client knows which one it spent.
func admitFromBudget(w http.ResponseWriter, id identity, limiter *application.RateLimiter, what string) bool {
	d := limiter.Take(id.UserID)
	if d.Allowed {
		return true
	}
	wait := d.RetryAfterSeconds()
	if d.NewEpisode {
		// One line per episode of refusals, not one per refused request: the log
		// must not become the thing a flood fills. %q: the identifier is not trusted
		// to be a plain word.
		log.Printf("api-gateway: the %s of user %q are refused: more than %d at once, then one every %s (written once per episode, not per refused request)",
			what, id.UserID, limiter.Capacity(), limiter.Refill().Round(time.Millisecond))
	}
	w.Header().Set("Retry-After", strconv.Itoa(wait))
	http.Error(w, fmt.Sprintf("too many %s from this user (at most %d at once, then one every %s): retry in %d s",
		what, limiter.Capacity(), limiter.Refill().Round(time.Millisecond), wait), http.StatusTooManyRequests)
	return false
}

// -- POST /sessions — the identity-injection case -------------------------
// -- GET  /sessions — the requests the caller may decide (ADR-0012) ---------

func (g *GatewayServer) handleSessionsCollection(w http.ResponseWriter, r *http.Request, id identity) {
	switch r.Method {
	case http.MethodGet:
		g.handleListPending(w, r, id)
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Before anything is read or forwarded: a request refused here never reaches the
	// Broker, so it writes no row and no audit event (ADR-0014).
	if !g.admitSessionRequest(w, id) {
		return
	}
	var body map[string]any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// The whole point of doing this at the Gateway: whatever the client
	// put in these two fields is discarded and replaced with the
	// Gateway's own verified identity (docs/architecture/system-overview.md, "injection de
	// contexte d'identité"). A client cannot request a session on behalf
	// of another user or grant itself extra roles by editing its request
	// body — see http_test.go's
	// TestHandleSessionsCollection_InjectsVerifiedIdentityOverridingClientClaims.
	body["requestedBy"] = id.UserID
	body["actorRoles"] = id.Roles

	g.forwardJSON(w, r.Context(), http.MethodPost, g.sessionBrokerURL+"/sessions", body)
}

// forwardRead reads one session for the user the token proves (ADR-0019). The Broker's
// query is built from nothing the client sent: a callerId or actorRoles in the client's
// own query string never gets past here, so a client cannot read as the requester of a
// session, nor with the roles of somebody who may read them; nothing of its body is
// relayed either. It costs nothing at the Gateway, which writes nothing for it (ADR-0016,
// rule 1); what the Broker records of a read is the Broker's (ADR-0020, ADR-0021).
func (g *GatewayServer) forwardRead(w http.ResponseWriter, r *http.Request, brokerPath string, id identity) {
	q := neturl.Values{}
	q.Set("callerId", id.UserID)
	q.Set("actorRoles", strings.Join(id.Roles, ","))
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, brokerPath+"?"+q.Encode(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	g.doAndRelay(w, req)
}

// handleListPending builds the Broker's query from nothing the client sent but the
// three parameters of the listing. Who is asking, and with which roles, is the verified
// token's: a callerId or actorRoles in the client's own query string never gets past
// here, so a client cannot list as an approver, nor as someone who is not its author
// (ADR-0012, rule 3). Nothing of the client's body is relayed either.
func (g *GatewayServer) handleListPending(w http.ResponseWriter, r *http.Request, id identity) {
	q := neturl.Values{}
	for _, key := range []string{"status", "page", "pageSize"} {
		if v := r.URL.Query().Get(key); v != "" {
			q.Set(key, v)
		}
	}
	q.Set("callerId", id.UserID)
	q.Set("actorRoles", strings.Join(id.Roles, ","))

	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, g.sessionBrokerURL+"/sessions?"+q.Encode(), nil)
	if err != nil {
		internalError(w, err)
		return
	}
	g.doAndRelay(w, req)
}

// -- /sessions/{id}[/connect|/approve|/reject|/recording] -------------------
//
// The session routes the Gateway knows, and only those. Anything else under
// /sessions/ is a 404 that never reaches the Session Broker: a route added to the
// Broker is therefore not relayed raw by default — it is exposed when someone
// writes its case here, with its identity injection (ADR-0011).
//
//	GET        /sessions/{id}      the Gateway states who is asking, and with which roles
//	                               (ADR-0019); reading is free of the action budget
//	DELETE     /sessions/{id}      the Gateway states who is asking, and with which roles
//	                               (ADR-0017); charged to the user's action budget
//	POST       …/connect           the Gateway states who is asking (callerId)
//	POST       …/approve|reject    the Gateway states who decides, and with which roles
//	GET        …/recording         served by the Command Recorder

func (g *GatewayServer) handleSessionItem(w http.ResponseWriter, r *http.Request, id identity) {
	sessionID, action, ok := splitSessionPath(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	brokerPath := g.sessionBrokerURL + "/sessions/" + neturl.PathEscape(sessionID)

	switch action {
	case "":
		switch r.Method {
		case http.MethodGet:
			g.forwardRead(w, r, brokerPath, id)
		case http.MethodDelete:
			// A refusal of somebody who may not end this session is an audit event, each
			// time: it is charged to the user's action budget first (ADR-0017), like the
			// other actions that write on every call.
			if !g.admitSessionAction(w, id) {
				return
			}
			// Who ends a session is the verified user, with the roles of that token: the
			// body is built here from nothing the client sent, so a client cannot end a
			// session as somebody else, nor give itself the role that may (ADR-0017).
			g.forwardJSON(w, r.Context(), http.MethodDelete, brokerPath,
				map[string]any{"callerId": id.UserID, "actorRoles": id.Roles})
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}

	case "recording":
		g.handleSessionRecording(w, r, id, sessionID)

	case "connect":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// Each call by the requester of an active session makes a Vault scope, a proxy
		// ticket and an audit event: it is charged to the user's action budget first
		// (ADR-0016), whatever the Broker will say.
		if !g.admitSessionAction(w, id) {
			return
		}
		// Only the requester may connect (ADR-0011, rule 7). The Broker believes the
		// callerId because only the Gateway may send it (ADR-0010); the client's own
		// body is not read, so it cannot name another caller.
		g.forwardJSON(w, r.Context(), http.MethodPost, brokerPath+"/connect", map[string]any{"callerId": id.UserID})

	case "approve", "reject":
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		// A refusal that says something about the caller is an audit event: every
		// attempt is charged to the user's action budget first (ADR-0016).
		if !g.admitSessionAction(w, id) {
			return
		}
		// The decision is the verified user's, with the roles of the verified token.
		// The body is built here from nothing the client sent: a client cannot decide
		// as someone else, nor grant itself the approval role (ADR-0011, rule 5).
		g.forwardJSON(w, r.Context(), http.MethodPost, brokerPath+"/"+action,
			map[string]any{"decidedBy": id.UserID, "actorRoles": id.Roles})

	default:
		http.NotFound(w, r)
	}
}

// splitSessionPath splits "/sessions/{id}" or "/sessions/{id}/{action}". Any other
// shape — an empty id, a third segment — is not a session route.
func splitSessionPath(path string) (sessionID, action string, ok bool) {
	rest := strings.TrimPrefix(path, "/sessions/")
	sessionID, action, hasAction := strings.Cut(rest, "/")
	// "/sessions/s1/" has a slash and no action: not a route either.
	if sessionID == "" || strings.Contains(action, "/") || (hasAction && action == "") {
		return "", "", false
	}
	return sessionID, action, true
}

// -- GET /sessions/{id}/recording (docs/api/rest/openapi.yaml) ---------------------------------
//
// The text recording of a session, served by the Command Recorder. The
// Gateway's part is to say who reads, and with which roles: both are the
// verified token's (ADR-0022), and the Recorder writes the read to the audit
// under that name before it serves it. The access decision itself
// (recording:session:read, RBAC) is the Recorder's. Only page and pageSize are
// taken from the client's query — nothing else reaches the Recorder, so a
// client-supplied callerId or actorRoles cannot either.

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
	q.Set("callerId", id.UserID)
	q.Set("actorRoles", strings.Join(id.Roles, ","))
	g.forwardPassthrough(w, r, http.MethodGet,
		g.commandRecorderURL+"/recorder/v1/sessions/"+neturl.PathEscape(sessionID)+"/commands?"+q.Encode())
}

// -- GET/POST /vault/accounts (mirrors docs/api/rest/openapi.yaml) --------------------------
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
// This is the one route in this increment that translates docs/api/rest/openapi.yaml's
// public REST shape into Password Vault's actual internal contract
// rather than passing the path straight through: docs/api/rest/openapi.yaml puts the account
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
		// docs/api/rest/openapi.yaml: an operator triggers rotation, never invents the value.
		g.forwardJSON(w, r.Context(), http.MethodPost, g.vaultURL+"/vault/v1/rotate", map[string]any{
			// Who asked, as verified here: the actor of the rotation's audit events (ADR-0037).
			"accountId": accountID, "actorRoles": id.Roles, "actorId": id.UserID,
		})
		return
	}

	// PUT /vault/accounts/{id}/host-key pins (or re-pins) the target's host key (ADR-0039).
	// Only the key is taken from the client: who pins, and with which roles, are the
	// verified token's — the Vault audits the change under that name.
	if accountID, ok := strings.CutSuffix(rest, "/host-key"); ok {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if accountID == "" || strings.Contains(accountID, "/") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			HostKey string `json:"hostKey"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "the body is not a host key", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPut, g.vaultURL+"/vault/v1/accounts/"+neturl.PathEscape(accountID)+"/host-key", map[string]any{
			"hostKey": body.HostKey, "actorRoles": id.Roles, "actorId": id.UserID,
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

	// Same principle as session creation (docs/architecture/system-overview.md): who created a
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

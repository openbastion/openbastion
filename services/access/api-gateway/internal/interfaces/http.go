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
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/coder/websocket"
	"github.com/openbastion/openbastion/pkg/screenstream"
	recordingv1 "github.com/openbastion/openbastion/proto/recording/v1"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	gatewayinfra "github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// VideoRecorderClient reads video segments and timeline events after the Gateway verifies the user's token.
type VideoRecorderClient interface {
	GetVideoSegment(ctx context.Context, sessionID string, firstSequence int64, actorID string, roles []string) (*recordingv1.GetVideoSegmentResponse, error)
	GetVideoEvents(ctx context.Context, sessionID, cursor string, limit int32, actorID string, roles []string) (*recordingv1.GetVideoEventsResponse, error)
}

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
	actionLimiter             *application.RateLimiter
	vaultAccountActionLimiter *application.RateLimiter
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
	auditURL           string
	videoRecorder      VideoRecorderClient
	httpClient         *http.Client
	screenAttaches     *gatewayinfra.ScreenAttachRegistry
	screenDialer       interface {
		Dial(context.Context, string, string) (*websocket.Conn, error)
	}
	screenCookieSecure bool
	screenOrigins      []string
	// ldapInfo remembers, a short while, whether directory login is on (ADR-0061).
	ldapInfo providersCache
	// oidcInfo remembers, a short while, which OIDC providers are on (ADR-0076).
	oidcInfo providersCache
}

func NewGatewayServer(authClient application.TokenVerifier, requestLimiter, loginLimiter *application.RateLimiter, authenticationURL, sessionBrokerURL, vaultURL, authorizationURL, commandRecorderURL string) *GatewayServer {
	return &GatewayServer{
		authClient: authClient, requestLimiter: requestLimiter, loginLimiter: loginLimiter,
		sessionLimiter:            application.NewSessionRequestLimiter(0, 0),
		actionLimiter:             application.NewSessionActionLimiter(0, 0),
		vaultAccountActionLimiter: application.NewVaultAccountActionLimiter(0, 0),
		proxyTrust:                &application.ProxyTrust{},
		authenticationURL:         authenticationURL, sessionBrokerURL: sessionBrokerURL,
		vaultURL: vaultURL, authorizationURL: authorizationURL, commandRecorderURL: commandRecorderURL,
		httpClient:     http.DefaultClient,
		screenAttaches: gatewayinfra.NewScreenAttachRegistry(), screenCookieSecure: true,
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

func (g *GatewayServer) WithVaultAccountActionLimiter(l *application.RateLimiter) *GatewayServer {
	if l != nil {
		g.vaultAccountActionLimiter = l
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

// WithAuditServiceURL configures the mTLS-protected Audit Service used by the read-only operator projection.
func (g *GatewayServer) WithAuditServiceURL(url string) *GatewayServer {
	g.auditURL = strings.TrimRight(url, "/")
	return g
}

// WithVideoRecorderClient installs the internal reader; a nil client keeps replay fail-closed.
func (g *GatewayServer) WithVideoRecorderClient(client VideoRecorderClient) *GatewayServer {
	g.videoRecorder = client
	return g
}

// WithScreenOrigins names the other origins a screen WebSocket may come from
// (SCREEN_ALLOWED_ORIGINS, ADR-0071 §10). Without any, only the Gateway's own origin may: the
// cookie that attaches a session must not be usable from another site's page.
func (g *GatewayServer) WithScreenOrigins(patterns []string) *GatewayServer {
	g.screenOrigins = append([]string(nil), patterns...)
	return g
}

// WithScreenAttach wires the one-use Gateway-to-proxy WebSocket relay. Cookie Secure
// defaults to true; development over plain HTTP must explicitly opt out by name.
func (g *GatewayServer) WithScreenAttach(d interface {
	Dial(context.Context, string, string) (*websocket.Conn, error)
}, secureCookie bool) *GatewayServer {
	g.screenDialer = d
	g.screenCookieSecure = secureCookie
	return g
}

func (g *GatewayServer) handleSessionRoute(w http.ResponseWriter, r *http.Request) {
	if sessionID, action, ok := splitSessionPath(r.URL.Path); ok && action == "screen" {
		g.handleScreenAttach(w, r, sessionID)
		return
	}
	g.requireAuth(g.handleSessionItem)(w, r)
}

func (g *GatewayServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/login", g.handleLogin) // public
	// Federated login (ADR-0035), public and in the login budget.
	mux.HandleFunc("/auth/oidc", g.handleOIDCInfo) // which providers (ADR-0076), public, from a short cache
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
	// One more key (ADR-0066): the current key's signature and an administrator's code.
	mux.HandleFunc("/auth/mfa/webauthn/keys/add", g.handleMFA("/auth/v1/mfa/webauthn/keys/add", "challenge", "{credential}", "enrollmentCode"))
	mux.HandleFunc("/auth/me/capabilities", g.requireAuth(g.handleCapabilities)) // ADR-0131
	mux.HandleFunc("/sessions", g.requireAuth(g.handleSessionsCollection))
	// The search of recorded commands (ADR-0080), served by the Command Recorder.
	mux.HandleFunc("/recordings/search", g.requireAuth(g.handleRecordingSearch))
	// Cross-session injection audit is a separate permission, never implied by session or platform roles (ADR-0113).
	mux.HandleFunc("/audit/secret-injections", g.requireAuth(g.handleSecretInjectionReconciliation))
	// The search of sessions (ADR-0080), more specific than /sessions/{id}.
	mux.HandleFunc("/sessions/search", g.requireAuth(g.handleSessionSearch))
	mux.HandleFunc("/sessions/", g.handleSessionRoute)
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
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if rejectUpstreamError(w, resp) {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	_, _ = io.Copy(w, resp.Body)
}

// -- POST /auth/oidc/start, /auth/oidc/callback (public, ADR-0035) -------

// handleOIDC forwards one end of a federated login to the Authentication Service. Each call
// takes from the same per-address budget as a password login: both are what an attacker who
// holds nothing can hammer. Only the provider (start, ADR-0076), or code and state (callback), are
// forwarded, rebuilt, never the raw body.
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
		if strings.HasSuffix(upstream, "/start") {
			var in struct {
				Provider string `json:"provider,omitempty"`
			}
			if err := json.NewDecoder(io.LimitReader(r.Body, 4<<10)).Decode(&in); err != nil && !errors.Is(err, io.EOF) {
				http.Error(w, "the body is not a start", http.StatusBadRequest)
				return
			}
			body, _ = json.Marshal(in)
		}
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
			http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
			return
		}
		defer resp.Body.Close()
		if rejectUpstreamError(w, resp) {
			return
		}
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
		// A transport failure is a Bad Gateway, not an upstream HTTP response.
		// Keep the public body generic so the internal address is never exposed.
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if rejectUpstreamError(w, resp) {
		return
	}
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

func (g *GatewayServer) admitVaultAccountAction(w http.ResponseWriter, id identity) bool {
	return admitFromBudget(w, id, g.vaultAccountActionLimiter, "vault account actions")
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
//	GET        …/recording/video/segments/{sequence} served by the Video Recorder
//	GET        …/recording/video/events served by the Video Recorder

func (g *GatewayServer) handleSessionItem(w http.ResponseWriter, r *http.Request, id identity) {
	if sessionID, matched := splitVideoRecordingEventsPath(r.URL.EscapedPath()); matched {
		if !usableVideoSessionID(sessionID) {
			writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video recording path")
			return
		}
		g.handleSessionVideoEvents(w, r, id, sessionID)
		return
	}
	if sessionID, firstSequence, matched := splitVideoRecordingPath(r.URL.EscapedPath()); matched {
		if !usableVideoSessionID(sessionID) || firstSequence < 1 {
			writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video recording path")
			return
		}
		g.handleSessionVideoRecording(w, r, id, sessionID, firstSequence)
		return
	}
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
		g.handleConnectAction(w, r, brokerPath+"/connect", sessionID, id.UserID)

	case "secret-injection-step-up":
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !g.admitSessionAction(w, id) {
			return
		}
		// The challenge request has no client-controlled fields. The verified identity
		// and roles are injected here; the Broker derives account/protocol from storage.
		data, readErr := io.ReadAll(io.LimitReader(r.Body, 1))
		if readErr != nil || len(data) != 0 {
			http.Error(w, "step-up request body must be empty", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPost, brokerPath+"/secret-injection-step-up",
			map[string]any{"callerId": id.UserID, "actorRoles": id.Roles})

	case "secret-injection":
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !g.admitSessionAction(w, id) {
			return
		}
		var proof secretInjectionProofRequest
		dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&proof); err != nil || proof.Challenge == "" || proof.Factor == "" {
			http.Error(w, "invalid secret injection proof", http.StatusBadRequest)
			return
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			http.Error(w, "invalid secret injection proof", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPost, brokerPath+"/secret-injection", secretInjectionBrokerRequest{
			CallerID: id.UserID, ActorRoles: id.Roles,
			Challenge: proof.Challenge, Factor: proof.Factor,
			TOTPCode: proof.TOTPCode, WebAuthnResponse: proof.WebAuthnResponse,
		})

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

func splitVideoRecordingEventsPath(escapedPath string) (string, bool) {
	if !strings.HasPrefix(escapedPath, "/sessions/") {
		return "", false
	}
	parts := strings.Split(strings.TrimPrefix(escapedPath, "/sessions/"), "/")
	if len(parts) != 4 || parts[1] != "recording" || parts[2] != "video" || parts[3] != "events" {
		return "", false
	}
	sessionID, err := neturl.PathUnescape(parts[0])
	return sessionID, err == nil
}

func (g *GatewayServer) handleSessionVideoEvents(w http.ResponseWriter, r *http.Request, id identity, sessionID string) {
	if r.Method != http.MethodGet {
		writeVideoRecordingAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if r.Body != nil && r.Body != http.NoBody {
		writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "video event requests do not accept a body")
		return
	}
	query := r.URL.Query()
	for key, values := range query {
		if (key != "cursor" && key != "limit") || len(values) != 1 {
			writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video event query")
			return
		}
	}
	cursor := query.Get("cursor")
	if len(cursor) > 1024 {
		writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video event cursor")
		return
	}
	limit := int64(50)
	if raw := query.Get("limit"); raw != "" {
		parsed, err := strconv.ParseInt(raw, 10, 32)
		if err != nil || parsed < 1 || parsed > 100 {
			writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video event limit")
			return
		}
		limit = parsed
	}
	if g.videoRecorder == nil {
		writeVideoRecordingAPIError(w, http.StatusServiceUnavailable, "VIDEO_RECORDER_UNAVAILABLE", "video recording unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	response, err := g.videoRecorder.GetVideoEvents(ctx, sessionID, cursor, int32(limit), id.UserID, id.Roles)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		writeVideoEventsError(w, err)
		return
	}
	result, err := toVideoEventsResponse(response, sessionID)
	if err != nil {
		log.Printf("api-gateway: Video Recorder returned invalid video event page: %v", err)
		writeVideoRecordingAPIError(w, http.StatusBadGateway, "VIDEO_RECORDER_INVALID_RESPONSE", "video recording unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("api-gateway: writing video event response failed: %v", err)
	}
}

type videoRecordingEventResponse struct {
	EventID    string    `json:"eventId"`
	SessionID  string    `json:"sessionId"`
	EventType  string    `json:"eventType"`
	Protocol   string    `json:"protocol"`
	Source     string    `json:"source"`
	AccountID  string    `json:"accountId"`
	OccurredAt time.Time `json:"occurredAt"`
	// An operator's password (ADR-0133): its size and salted fingerprint, never its text.
	PasteBytes  int    `json:"pasteBytes,omitempty"`
	PasteSalt   string `json:"pasteSalt,omitempty"`
	PasteSHA256 string `json:"pasteSha256,omitempty"`
}

type videoEventsResponse struct {
	Events     []videoRecordingEventResponse `json:"events"`
	NextCursor string                        `json:"nextCursor,omitempty"`
}

func toVideoEventsResponse(response *recordingv1.GetVideoEventsResponse, sessionID string) (videoEventsResponse, error) {
	if response == nil || len(response.GetEvents()) > 100 || len(response.GetNextCursor()) > 1024 {
		return videoEventsResponse{}, fmt.Errorf("invalid video event page bounds")
	}
	for _, character := range response.GetNextCursor() {
		if !((character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '_' || character == '-') {
			return videoEventsResponse{}, fmt.Errorf("invalid video event cursor")
		}
	}
	result := videoEventsResponse{Events: make([]videoRecordingEventResponse, 0, len(response.GetEvents())), NextCursor: response.GetNextCursor()}
	var previous time.Time
	var previousID string
	for i, event := range response.GetEvents() {
		if event == nil || event.GetSessionId() != sessionID || len(event.GetEventId()) > 128 || !usableVideoSessionID(event.GetEventId()) ||
			!validVideoEventKind(event) || (event.GetProtocol() != "vnc" && event.GetProtocol() != "rdp") ||
			len(event.GetAccountId()) > 256 || !usableVideoSessionID(event.GetAccountId()) ||
			event.GetOccurredAt() == nil || event.GetOccurredAt().CheckValid() != nil {
			return videoEventsResponse{}, fmt.Errorf("event %d is invalid", i)
		}
		occurred := event.GetOccurredAt().AsTime()
		if i > 0 && (occurred.Before(previous) || (occurred.Equal(previous) && event.GetEventId() <= previousID)) {
			return videoEventsResponse{}, fmt.Errorf("event order is invalid")
		}
		previous, previousID = occurred, event.GetEventId()
		result.Events = append(result.Events, videoRecordingEventResponse{EventID: event.GetEventId(), SessionID: sessionID, EventType: event.GetEventType(), Protocol: event.GetProtocol(), Source: event.GetSource(), AccountID: event.GetAccountId(), OccurredAt: occurred,
			PasteBytes: int(event.GetPasteBytes()), PasteSalt: event.GetPasteSalt(), PasteSHA256: event.GetPasteSha256()})
	}
	return result, nil
}

// validVideoEventKind: a Vault secret's marker (no fingerprint), or an operator's password's (its
// size, salt and salted fingerprint, ADR-0133), as the Video Recorder writes them.
func validVideoEventKind(event *recordingv1.VideoRecordingEvent) bool {
	hex := func(value string, length int) bool {
		if len(value) != length {
			return false
		}
		for _, c := range value {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				return false
			}
		}
		return true
	}
	switch {
	case event.GetEventType() == "secret_injection_started" && event.GetSource() == "vault":
		return event.GetPasteBytes() == 0 && event.GetPasteSalt() == "" && event.GetPasteSha256() == ""
	case event.GetEventType() == "secret_paste_started" && event.GetSource() == "operator":
		return event.GetPasteBytes() >= 1 && event.GetPasteBytes() <= 512 && hex(event.GetPasteSalt(), 32) && hex(event.GetPasteSha256(), 64)
	}
	return false
}

func splitVideoRecordingPath(escapedPath string) (string, int64, bool) {
	if !strings.HasPrefix(escapedPath, "/sessions/") {
		return "", 0, false
	}
	parts := strings.Split(strings.TrimPrefix(escapedPath, "/sessions/"), "/")
	if len(parts) < 3 || parts[1] != "recording" || parts[2] != "video" {
		return "", 0, false
	}
	if len(parts) != 5 || parts[3] != "segments" {
		return "", 0, true
	}
	sessionID, err := neturl.PathUnescape(parts[0])
	if err != nil {
		return "", 0, true
	}
	sequence, err := strconv.ParseInt(parts[4], 10, 64)
	if err != nil {
		return sessionID, 0, true
	}
	return sessionID, sequence, true
}

func usableVideoSessionID(sessionID string) bool {
	if sessionID == "" || len(sessionID) > 256 || !utf8.ValidString(sessionID) {
		return false
	}
	for _, character := range sessionID {
		if unicode.IsControl(character) {
			return false
		}
	}
	return true
}

func (g *GatewayServer) handleSessionVideoRecording(w http.ResponseWriter, r *http.Request, id identity, sessionID string, firstSequence int64) {
	if r.Method != http.MethodGet {
		writeVideoRecordingAPIError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "method not allowed")
		return
	}
	if r.URL.RawQuery != "" || (r.Body != nil && r.Body != http.NoBody) {
		writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "video recording requests do not accept a body or query parameters")
		return
	}
	if g.videoRecorder == nil {
		log.Printf("api-gateway: Video Recorder client is not configured")
		writeVideoRecordingAPIError(w, http.StatusServiceUnavailable, "VIDEO_RECORDER_UNAVAILABLE", "video recording unavailable")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	response, err := g.videoRecorder.GetVideoSegment(ctx, sessionID, firstSequence, id.UserID, id.Roles)
	if err != nil {
		if r.Context().Err() != nil {
			return
		}
		writeVideoRecordingError(w, err)
		return
	}
	result, err := toVideoSegmentResponse(response, sessionID, firstSequence)
	if err != nil {
		log.Printf("api-gateway: Video Recorder returned an invalid segment: %v", err)
		writeVideoRecordingAPIError(w, http.StatusBadGateway, "VIDEO_RECORDER_INVALID_RESPONSE", "video recording unavailable")
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(result); err != nil {
		log.Printf("api-gateway: writing video segment response failed: %v", err)
	}
}

type videoSegmentResponse struct {
	SessionID     string               `json:"sessionId"`
	FirstSequence int64                `json:"firstSequence"`
	LastSequence  int64                `json:"lastSequence"`
	Frames        []videoFrameResponse `json:"frames"`
	Complete      bool                 `json:"complete"`
}

type videoFrameResponse struct {
	Timestamp time.Time `json:"timestamp"`
	FrameData []byte    `json:"frameData"`
	Codec     string    `json:"codec"`
}

func toVideoSegmentResponse(response *recordingv1.GetVideoSegmentResponse, sessionID string, firstSequence int64) (videoSegmentResponse, error) {
	if response == nil || response.GetSessionId() != sessionID ||
		response.GetFirstSequence() != firstSequence ||
		response.GetLastSequence() < firstSequence ||
		response.GetLastSequence()-firstSequence != int64(len(response.GetFrames()))-1 ||
		len(response.GetFrames()) == 0 {
		return videoSegmentResponse{}, fmt.Errorf("segment identity or sequence bounds do not match")
	}
	result := videoSegmentResponse{
		SessionID: sessionID, FirstSequence: firstSequence,
		LastSequence: response.GetLastSequence(), Complete: response.GetComplete(),
		Frames: make([]videoFrameResponse, 0, len(response.GetFrames())),
	}
	var totalBytes int64
	var lastTimestamp time.Time
	for index, frame := range response.GetFrames() {
		if frame == nil || frame.GetTs() == nil || frame.GetTs().CheckValid() != nil ||
			(frame.GetCodec() != "png" && frame.GetCodec() != "png-delta-v1" && frame.GetCodec() != "clipboard-text-v1") ||
			len(frame.GetFrameData()) == 0 || len(frame.GetFrameData()) > 4<<20 {
			return videoSegmentResponse{}, fmt.Errorf("frame %d is invalid", index)
		}
		// A partial frame (ADR-0092) is the FRAME_DELTA message of its own sequence, as the Recorder
		// validated it: checked again here, as the Recorder is a trust boundary.
		if frame.GetCodec() == "png-delta-v1" {
			message, err := screenstream.Decode(frame.GetFrameData())
			if err != nil || message.Type != screenstream.TypeFrameDelta || int64(message.Sequence) != firstSequence+int64(index) {
				return videoSegmentResponse{}, fmt.Errorf("frame %d is not the partial frame of its sequence", index)
			}
		}
		// A clipboard text (ADR-0096 §4) is the CLIPBOARD message of its own sequence, likewise.
		if frame.GetCodec() == "clipboard-text-v1" {
			message, err := screenstream.Decode(frame.GetFrameData())
			if err != nil || message.Type != screenstream.TypeClipboard || int64(message.Sequence) != firstSequence+int64(index) {
				return videoSegmentResponse{}, fmt.Errorf("frame %d is not the clipboard text of its sequence", index)
			}
		}
		totalBytes += int64(len(frame.GetFrameData()))
		if totalBytes > 4<<20 {
			return videoSegmentResponse{}, fmt.Errorf("segment exceeds the frame data limit")
		}
		timestamp := frame.GetTs().AsTime()
		if index > 0 && timestamp.Before(lastTimestamp) {
			return videoSegmentResponse{}, fmt.Errorf("frame timestamps are not ordered")
		}
		lastTimestamp = timestamp
		result.Frames = append(result.Frames, videoFrameResponse{
			Timestamp: timestamp, FrameData: frame.GetFrameData(), Codec: frame.GetCodec(),
		})
	}
	return result, nil
}

func writeVideoEventsError(w http.ResponseWriter, err error) {
	if status.Code(err) == codes.NotFound {
		writeVideoRecordingAPIError(w, http.StatusNotFound, "VIDEO_RECORDING_NOT_FOUND", "video recording not found")
		return
	}
	writeVideoRecordingError(w, err)
}

func writeVideoRecordingError(w http.ResponseWriter, err error) {
	switch status.Code(err) {
	case codes.InvalidArgument:
		writeVideoRecordingAPIError(w, http.StatusBadRequest, "VIDEO_RECORDING_INVALID_REQUEST", "invalid video recording request")
	case codes.PermissionDenied:
		writeVideoRecordingAPIError(w, http.StatusForbidden, "VIDEO_RECORDING_ACCESS_DENIED", "video recording access denied")
	case codes.NotFound:
		writeVideoRecordingAPIError(w, http.StatusNotFound, "VIDEO_SEGMENT_NOT_FOUND", "video segment not found")
	case codes.FailedPrecondition:
		writeVideoRecordingAPIError(w, http.StatusConflict, "VIDEO_RECORDING_CONFLICT", "video recording state conflict")
	case codes.Unavailable, codes.DeadlineExceeded:
		log.Printf("api-gateway: Video Recorder unavailable (gRPC status %s)", status.Code(err))
		writeVideoRecordingAPIError(w, http.StatusServiceUnavailable, "VIDEO_RECORDER_UNAVAILABLE", "video recording unavailable")
	default:
		log.Printf("api-gateway: Video Recorder request failed (gRPC status %s)", status.Code(err))
		writeVideoRecordingAPIError(w, http.StatusBadGateway, "VIDEO_RECORDER_ERROR", "video recording unavailable")
	}
}

type videoRecordingAPIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeVideoRecordingAPIError(w http.ResponseWriter, statusCode int, code, message string) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	if err := json.NewEncoder(w).Encode(videoRecordingAPIError{Code: code, Message: message}); err != nil {
		log.Printf("api-gateway: writing video recording error response failed: %v", err)
	}
}

// splitSessionPath splits "/sessions/{id}" or "/sessions/{id}/{action}". Any other
// shape — an empty id, a third segment — is not a session route.
type brokerConnectionTicket struct {
	ProxyEndpoint string    `json:"proxyEndpoint"`
	Ticket        string    `json:"ticket"`
	Protocol      string    `json:"protocol"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

type secretInjectionProofRequest struct {
	Challenge        string          `json:"challenge"`
	Factor           string          `json:"factor"`
	TOTPCode         string          `json:"totp_code,omitempty"`
	WebAuthnResponse json.RawMessage `json:"webauthn_response,omitempty"`
}

type secretInjectionBrokerRequest struct {
	CallerID         string          `json:"callerId"`
	ActorRoles       []string        `json:"actorRoles"`
	Challenge        string          `json:"challenge"`
	Factor           string          `json:"factor"`
	TOTPCode         string          `json:"totp_code,omitempty"`
	WebAuthnResponse json.RawMessage `json:"webauthn_response,omitempty"`
}
type screenAttachResponse struct {
	Protocol  string    `json:"protocol"`
	Attach    string    `json:"attach"`
	ExpiresAt time.Time `json:"expiresAt"`
}

// connectBody is the public body of POST /sessions/{id}/connect, optional (ADR-0132): the
// operator's screen choice for an RDP session. The Broker resolves it against the account's
// profile; the Gateway only checks its shape.
type connectBody struct {
	Screen *connectScreenChoice `json:"screen,omitempty"`
}

type connectScreenChoice struct {
	Channel    string `json:"channel,omitempty"`
	ColorDepth int    `json:"colorDepth,omitempty"`
}

// brokerConnectRequest is what the Broker reads: the caller from the verified token, never
// from the body, and the screen choice as it came.
type brokerConnectRequest struct {
	CallerID string               `json:"callerId"`
	Screen   *connectScreenChoice `json:"screen,omitempty"`
}

// readConnectBody reads the optional body: none, or one JSON object. Other fields are ignored, as
// they were before the body had any (a client's "callerId" never survives: the caller is the
// token's); a screen of the wrong shape is refused.
func readConnectBody(w http.ResponseWriter, r *http.Request) (connectBody, error) {
	var body connectBody
	data, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 4<<10))
	if err != nil {
		return body, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return body, nil
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&body); err != nil {
		return body, err
	}
	if dec.More() {
		return body, errors.New("trailing data")
	}
	return body, nil
}

func (g *GatewayServer) handleConnectAction(w http.ResponseWriter, r *http.Request, url, sessionID, callerID string) {
	choice, err := readConnectBody(w, r)
	if err != nil {
		http.Error(w, "invalid connect request", http.StatusBadRequest)
		return
	}
	body, _ := json.Marshal(brokerConnectRequest{CallerID: callerID, Screen: choice.Screen})
	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		internalError(w, err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.httpClient.Do(req)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	defer resp.Body.Close()
	if rejectUpstreamError(w, resp) {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusServiceUnavailable)
		return
	}
	if resp.StatusCode != http.StatusOK {
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		return
	}
	var ticket brokerConnectionTicket
	if err := json.Unmarshal(data, &ticket); err != nil {
		http.Error(w, "invalid connection response", http.StatusBadGateway)
		return
	}
	// A screen ticket (VNC, and RDP since ADR-0088) never reaches the browser: only SSH's answer
	// goes through as it came.
	if ticket.Protocol != "vnc" && ticket.Protocol != "rdp" {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(data)
		return
	}
	if g.screenAttaches == nil || g.screenDialer == nil || ticket.Ticket == "" || ticket.ProxyEndpoint == "" || !ticket.ExpiresAt.After(time.Now()) {
		// Do not leak a screen ticket to the browser when the secure attach path is unavailable.
		http.Error(w, "screen attach unavailable", http.StatusServiceUnavailable)
		return
	}
	attachPath := "/sessions/" + neturl.PathEscape(sessionID) + "/screen"
	expires := time.Now().Add(30 * time.Second)
	if ticket.ExpiresAt.Before(expires) {
		expires = ticket.ExpiresAt
	}
	attachToken, err := g.screenAttaches.Register(gatewayinfra.ScreenAttach{SessionID: sessionID, UserID: callerID, Endpoint: ticket.ProxyEndpoint, Ticket: ticket.Ticket, ExpiresAt: expires})
	if err != nil {
		http.Error(w, "screen attach unavailable", http.StatusServiceUnavailable)
		return
	}
	maxAge := int(time.Until(expires).Seconds())
	if maxAge < 1 {
		http.Error(w, "screen attach expired", http.StatusConflict)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "ob_screen_attach", Value: attachToken, Path: attachPath, Expires: expires, MaxAge: maxAge, HttpOnly: true, Secure: g.screenCookieSecure, SameSite: http.SameSiteStrictMode})
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(screenAttachResponse{Protocol: ticket.Protocol, Attach: attachPath, ExpiresAt: expires})
}

func (g *GatewayServer) handleScreenAttach(w http.ResponseWriter, r *http.Request, sessionID string) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "query parameters are not accepted", http.StatusBadRequest)
		return
	}
	cookie, err := r.Cookie("ob_screen_attach")
	if err != nil || cookie.Value == "" {
		http.Error(w, "screen attach expired or unavailable", http.StatusUnauthorized)
		return
	}
	if g.screenAttaches == nil || g.screenDialer == nil {
		http.Error(w, "screen attach unavailable", http.StatusServiceUnavailable)
		return
	}
	client, err := websocket.Accept(w, r, &websocket.AcceptOptions{Subprotocols: []string{"openbastion.screen.v1"}, OriginPatterns: g.screenOrigins})
	if err != nil {
		return
	}
	defer client.Close(websocket.StatusNormalClosure, "screen session ended")
	attach, err := g.screenAttaches.Consume(cookie.Value, sessionID, time.Now())
	if err != nil {
		writeScreenEnd(client, screenstream.EndCodeTicketInvalid, "ticket_invalid")
		_ = client.Close(websocket.StatusPolicyViolation, "invalid attach")
		return
	}
	defer g.screenAttaches.ReleaseSession(sessionID)
	if !g.screenAttaches.AllowUpgrade(attach.UserID, time.Now()) {
		_ = client.Close(websocket.StatusTryAgainLater, "screen upgrade rate limit")
		return
	}
	upstream, err := g.screenDialer.Dial(r.Context(), attach.Endpoint, attach.Ticket)
	if err != nil {
		_ = client.Close(websocket.StatusTryAgainLater, "screen proxy unavailable")
		return
	}
	defer upstream.Close(websocket.StatusNormalClosure, "gateway relay ended")
	// A clipboard text is the longest thing a client sends (ADR-0096 §6); the proxy holds a session
	// that may not paste to 64 bytes.
	client.SetReadLimit(screenstream.MaxClipboardInputBytes)
	upstream.SetReadLimit(screenstream.MaxPNGBytes + screenstream.HeaderSize + screenstream.MaxSessionIDBytes + 1024)
	if err := relayScreenWebSockets(r.Context(), client, upstream); err != nil {
		log.Printf("api-gateway: screen relay ended for session %s", sessionID)
	}
}

// validScreenInput reads a client's message as strictly as the proxy reads it: an input of 16
// bytes, or a clipboard text (ADR-0096 §6).
func validScreenInput(data []byte) error {
	if screenstream.IsClipboardInput(data) {
		_, err := screenstream.DecodeClipboardInput(data)
		return err
	}
	if len(data) != screenstream.InputMessageSize {
		return screenstream.ErrMalformedMessage
	}
	_, err := screenstream.DecodeInput(data, screenstream.MaxPixels, screenstream.MaxPixels)
	return err
}

func writeScreenEnd(conn *websocket.Conn, code uint16, text string) {
	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	data, err := screenstream.Encode(screenstream.Message{Type: screenstream.TypeEnd, Sequence: 1, Timestamp: time.Now().UTC(), EndCode: code, Text: text})
	if err != nil {
		return
	}
	_ = conn.Write(ctx, websocket.MessageBinary, data)
}

func relayScreenWebSockets(ctx context.Context, client, upstream *websocket.Conn) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errs := make(chan error, 2)
	go func() {
		for {
			typ, data, err := client.Read(ctx)
			if err != nil {
				errs <- err
				return
			}
			if typ != websocket.MessageBinary {
				errs <- screenstream.ErrMalformedMessage
				return
			}
			// An input of 16 bytes, or a clipboard text (ADR-0096 §6): each read as strictly as the
			// proxy reads it, before it goes on.
			if err := validScreenInput(data); err != nil {
				errs <- err
				return
			}
			if err := upstream.Write(ctx, websocket.MessageBinary, data); err != nil {
				errs <- err
				return
			}
		}
	}()
	go func() {
		for {
			typ, data, err := upstream.Read(ctx)
			if err != nil {
				errs <- err
				return
			}
			if typ != websocket.MessageBinary {
				errs <- screenstream.ErrUnsupported
				return
			}
			if _, err := screenstream.Decode(data); err != nil {
				errs <- err
				return
			}
			if err := client.Write(ctx, websocket.MessageBinary, data); err != nil {
				errs <- err
				return
			}
		}
	}()
	err := <-errs
	cancel()
	return err
}

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

// handleSessionSearch relays GET /sessions/search (ADR-0080): the search from the client, the
// caller and its roles from the verified token, nothing else.
func (g *GatewayServer) handleSessionSearch(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := neturl.Values{}
	for _, key := range []string{"q", "from", "to", "status", "protocol", "requestedBy", "privilegedAccountId", "breakGlass", "cursor"} {
		if v := r.URL.Query().Get(key); v != "" {
			q.Set(key, v)
		}
	}
	q.Set("callerId", id.UserID)
	q.Set("actorRoles", strings.Join(id.Roles, ","))
	g.forwardPassthrough(w, r, http.MethodGet, g.sessionBrokerURL+"/sessions/search?"+q.Encode())
}

// handleRecordingSearch relays GET /recordings/search (ADR-0080): q, from and to from the client,
// the caller and its roles from the verified token, nothing else.
func (g *GatewayServer) handleRecordingSearch(w http.ResponseWriter, r *http.Request, id identity) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := neturl.Values{}
	for _, key := range []string{"q", "from", "to"} {
		q.Set(key, r.URL.Query().Get(key))
	}
	q.Set("callerId", id.UserID)
	q.Set("actorRoles", strings.Join(id.Roles, ","))
	g.forwardPassthrough(w, r, http.MethodGet, g.commandRecorderURL+"/recorder/v1/search?"+q.Encode())
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

	// PUT /vault/accounts/{id}/tls-pin pins the graphical target certificate and TLS name (ADR-0071).
	// The client supplies only the target identity; actor ID and roles always come from the verified token.
	if accountID, ok := strings.CutSuffix(rest, "/tls-pin"); ok {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if accountID == "" || strings.Contains(accountID, "/") {
			http.NotFound(w, r)
			return
		}
		var body struct {
			TLSCertificateSHA256 string `json:"tlsCertificateSha256"`
			TargetDomain         string `json:"targetDomain"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "invalid TLS pin request", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPut, g.vaultURL+"/vault/v1/accounts/"+neturl.PathEscape(accountID)+"/tls-pin", map[string]any{
			"tlsCertificateSha256": body.TLSCertificateSHA256,
			"targetDomain":         body.TargetDomain,
			"actorRoles":           id.Roles,
			"actorId":              id.UserID,
		})
		return
	}

	// PUT /vault/accounts/{id}/screen-profile sets what a session on an RDP account may use for its
	// screen (ADR-0132). Only the profile is the client's, in its known fields; who sets it, and with
	// which roles, are the verified token's — the Vault checks, validates and audits.
	if accountID, ok := strings.CutSuffix(rest, "/screen-profile"); ok {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if accountID == "" || strings.Contains(accountID, "/") {
			http.NotFound(w, r)
			return
		}
		// The same per-user budget as the approval setting (ADR-0067): an account action.
		if !g.admitVaultAccountAction(w, id) {
			return
		}
		var body struct {
			ScreenProfile *struct {
				Channels          []string `json:"channels"`
				DefaultChannel    string   `json:"defaultChannel"`
				ColorDepths       []int    `json:"colorDepths"`
				DefaultColorDepth int      `json:"defaultColorDepth"`
			} `json:"screenProfile"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "the body is {\"screenProfile\": {...} | null}", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPut, g.vaultURL+"/vault/v1/accounts/"+neturl.PathEscape(accountID)+"/screen-profile", map[string]any{
			"screenProfile": body.ScreenProfile, "actorRoles": id.Roles, "actorId": id.UserID,
		})
		return
	}

	// PUT /vault/accounts/{id}/kerberos sets the realm and KDCs of an RDP account, whose sessions
	// then authenticate with Kerberos alone (ADR-0100). Only the realm and KDCs are the client's;
	// who sets them, and with which roles, are the verified token's — the Vault checks, normalizes
	// and audits. The service principal is never the client's: the proxy derives it from the
	// account's pinned target name.
	if accountID, ok := strings.CutSuffix(rest, "/kerberos"); ok {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if accountID == "" || strings.Contains(accountID, "/") {
			http.NotFound(w, r)
			return
		}
		if !g.admitVaultAccountAction(w, id) {
			return
		}
		var body struct {
			Kerberos *struct {
				Realm string   `json:"realm"`
				KDCs  []string `json:"kdcs"`
			} `json:"kerberos"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil {
			http.Error(w, "the body is {\"kerberos\": {\"realm\": ..., \"kdcs\": [...]} | null}", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPut, g.vaultURL+"/vault/v1/accounts/"+neturl.PathEscape(accountID)+"/kerberos", map[string]any{
			"kerberos": body.Kerberos, "actorRoles": id.Roles, "actorId": id.UserID,
		})
		return
	}

	// PUT /vault/accounts/{id}/approval says whether a session on the account waits for another
	// person's approval (ADR-0067). The setting only is the client's; who sets it is the token's.
	if accountID, ok := strings.CutSuffix(rest, "/approval"); ok {
		if r.Method != http.MethodPut {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if accountID == "" || strings.Contains(accountID, "/") {
			http.NotFound(w, r)
			return
		}
		if !g.admitVaultAccountAction(w, id) {
			return
		}
		var body struct {
			ApprovalRequired *bool `json:"approvalRequired"`
		}
		if err := json.NewDecoder(io.LimitReader(r.Body, 16<<10)).Decode(&body); err != nil || body.ApprovalRequired == nil {
			http.Error(w, "the body is {\"approvalRequired\": true|false}", http.StatusBadRequest)
			return
		}
		g.forwardJSON(w, r.Context(), http.MethodPut, g.vaultURL+"/vault/v1/accounts/"+neturl.PathEscape(accountID)+"/approval", map[string]any{
			"approvalRequired": *body.ApprovalRequired, "actorRoles": id.Roles, "actorId": id.UserID,
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

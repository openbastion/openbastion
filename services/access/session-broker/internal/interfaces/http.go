// Package interfaces exposes SessionOrchestration
// (proto/access/v1/session_orchestration.proto) plus the Connect flow
// (docs/api/rest/openapi.yaml, POST /sessions/{id}/connect) over JSON/HTTP — see
// /NOTES_SANDBOX.md for why HTTP stands in for gRPC here.
//
// Every route under /sessions/* is safe to expose through the API Gateway
// to end clients — including /connect, now that it returns only a
// connection ticket (never the Vault scope token used to obtain it, see
// application.SessionBrokerService.Connect's doc comment). Earlier in
// this project's history this endpoint lived under /internal/v1/ for
// exactly that reason, before ssh-proxy existed to mint a real ticket —
// see NOTES_SANDBOX.md for that history.
package interfaces

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type HTTPServer struct {
	svc *application.SessionBrokerService
}

func NewHTTPServer(svc *application.SessionBrokerService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", s.handleSessionsCollection)
	mux.HandleFunc("/sessions/search", s.handleSearch) // ADR-0080; more specific than /sessions/
	mux.HandleFunc("/sessions/", s.handleSessionItem)  // /sessions/{id}, /sessions/{id}/connect
	mux.HandleFunc("/healthz", s.handleHealthz)
	return mux
}

func (s *HTTPServer) handleHealthz(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// -- POST /sessions (mirrors docs/api/rest/openapi.yaml) ---------------------------------

type createSessionRequest struct {
	RequestedBy         string   `json:"requestedBy"`
	ActorRoles          []string `json:"actorRoles"`
	PrivilegedAccountID string   `json:"targetAccountId"`
	Protocol            string   `json:"protocol"`
	Justification       string   `json:"justification"`
	DurationMinutes     int      `json:"durationMinutes"`

	// BreakGlass asks for the right to run while the Command Recorder is down
	// (ADR-0009). It is a request: it needs a justification, a bounded duration and
	// a RBAC policy on breakglass:account:{id}, or the session is refused.
	BreakGlass bool `json:"breakGlass"`

	// Ticket is the reference an account that requires approval asks for (ADR-0067), in
	// the declared format; ignored on any other account.
	Ticket json.RawMessage `json:"ticket"`
}

type sessionResponse struct {
	ID                  string `json:"id"`
	Status              string `json:"status"`
	Protocol            string `json:"protocol"`
	RequestedBy         string `json:"requestedBy"`
	PrivilegedAccountID string `json:"privilegedAccountId"`
	Justification       string `json:"justification"`
	BreakGlass          bool   `json:"breakGlass"`

	// ApprovalRequired and Ticket: an ordinary session that waited, or waits, for another
	// person's approval (ADR-0067), and the reference it was asked with.
	ApprovalRequired bool   `json:"approvalRequired,omitempty"`
	Ticket           string `json:"ticket,omitempty"`

	// ExpiresAt is the end of the session — or, while the status is
	// pending_approval, the deadline for a decision (ADR-0011).
	ExpiresAt string `json:"expiresAt"`

	// DecidedBy and DecidedAt say who approved or rejected a break-glass request,
	// and when. Absent for every session that was not decided on.
	DecidedBy string `json:"decidedBy,omitempty"`
	DecidedAt string `json:"decidedAt,omitempty"`
}

func toSessionResponse(s *domain.Session) sessionResponse {
	r := sessionResponse{
		ID: s.ID, Status: string(s.Status), Protocol: s.Protocol,
		RequestedBy: s.RequestedBy, PrivilegedAccountID: s.PrivilegedAccountID,
		Justification: s.Justification, BreakGlass: s.BreakGlass,
		ApprovalRequired: s.ApprovalRequired, Ticket: s.Ticket,
		ExpiresAt: s.ExpiresAt.UTC().Format(time.RFC3339), DecidedBy: s.DecidedBy,
	}
	if s.DecidedAt != nil {
		r.DecidedAt = s.DecidedAt.UTC().Format(time.RFC3339)
	}
	return r
}

func (s *HTTPServer) handleSessionsCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		s.handleListPending(w, r)
		return
	case http.MethodPost:
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req createSessionRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	var sess *domain.Session
	var err error
	if req.BreakGlass {
		sess, err = s.svc.CreateBreakGlassSession(r.Context(), req.RequestedBy, req.ActorRoles, req.PrivilegedAccountID, req.Protocol, req.Justification, req.DurationMinutes)
	} else {
		ticket := application.ApprovalTicketInput{IsString: len(req.Ticket) == 0}
		if len(req.Ticket) > 0 && req.Ticket[0] == '"' {
			ticket.IsString = json.Unmarshal(req.Ticket, &ticket.Value) == nil
		}
		sess, err = s.svc.CreateSessionWithTicketInput(r.Context(), req.RequestedBy, req.ActorRoles, req.PrivilegedAccountID, req.Protocol, req.Justification, ticket, req.DurationMinutes)
	}
	switch {
	case err == nil:
	case errors.Is(err, domain.ErrInvalidTicket):
		http.Error(w, domain.ErrInvalidTicket.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, domain.ErrUnsupportedProtocol):
		http.Error(w, domain.ErrUnsupportedProtocol.Error(), http.StatusConflict)
		return
	case errors.Is(err, domain.ErrProtocolMismatch):
		http.Error(w, domain.ErrProtocolMismatch.Error(), http.StatusConflict)
		return
	case errors.Is(err, domain.ErrAccountNotFound):
		http.Error(w, domain.ErrAccountNotFound.Error(), http.StatusNotFound)
		return
	case errors.Is(err, domain.ErrAccountNotPinned):
		http.Error(w, domain.ErrAccountNotPinned.Error(), http.StatusConflict)
		return
	case errors.Is(err, domain.ErrAccountTLSNotPinned):
		http.Error(w, domain.ErrAccountTLSNotPinned.Error(), http.StatusConflict)
		return
	case errors.Is(err, domain.ErrTooManyPending):
		// The requester's own quota (ADR-0013): it says how many, and it frees itself.
		http.Error(w, err.Error(), http.StatusTooManyRequests)
		return
	case errors.Is(err, domain.ErrUnavailable):
		// The requests waiting could not be counted: nothing was accepted. The cause
		// stays in this process's log, not in what a client reads.
		log.Printf("session-broker: a session request was not accepted: %v", err)
		http.Error(w, "the request could not be accepted: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
		return
	default:
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
}

// -- GET /sessions?status=pending_approval (ADR-0012) -------------------------

// listSessionsResponse follows GET /vault/accounts: items, then the page that was
// served and the total. Truncated appears only when it is true.
type listSessionsResponse struct {
	Items      []sessionResponse `json:"items"`
	Page       int               `json:"page"`
	PageSize   int               `json:"pageSize"`
	TotalItems int               `json:"totalItems"`
	Truncated  bool              `json:"truncated,omitempty"`
}

// handleListPending answers what the caller may decide. The caller is the one the
// Gateway verified (callerId) with the roles of that token (actorRoles, comma-
// separated like the Vault's and the Recorder's routes): the Gateway builds this
// query itself, and only an internal caller can reach it (ADR-0010).
func (s *HTTPServer) handleListPending(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	// Only one listing is served so far (ADR-0012, rule 2): saying so is better than
	// answering a different question than the one that was asked.
	if q.Get("status") != string(domain.StatusPendingApproval) {
		http.Error(w, "only status=pending_approval is served", http.StatusBadRequest)
		return
	}
	var roles []string
	if raw := q.Get("actorRoles"); raw != "" {
		roles = strings.Split(raw, ",")
	}
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))

	items, total, truncated, err := s.svc.ListPendingApprovals(r.Context(), q.Get("callerId"), roles, page, pageSize)
	switch {
	case err == nil:
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	default:
		// A dependency did not answer; the cause stays in this process's log.
		log.Printf("session-broker: listing the pending requests failed: %v", err)
		http.Error(w, "the list could not be built: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
		return
	}
	page, pageSize = application.ClampPage(page, pageSize) // the page SERVED, as GET /vault/accounts
	out := listSessionsResponse{Items: make([]sessionResponse, 0, len(items)), Page: page, PageSize: pageSize, TotalItems: total, Truncated: truncated}
	for _, sess := range items {
		out.Items = append(out.Items, toSessionResponse(sess))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// -- GET /sessions/{id}, DELETE /sessions/{id}, POST /sessions/{id}/connect|approve|reject --

func (s *HTTPServer) handleSessionItem(w http.ResponseWriter, r *http.Request) {
	rest := r.URL.Path[len("/sessions/"):]
	if rest == "" {
		http.Error(w, "missing session id", http.StatusBadRequest)
		return
	}

	for suffix, handle := range map[string]func(http.ResponseWriter, *http.Request, string){
		"/connect": s.handleConnect,
		"/approve": s.handleApprove,
		"/reject":  s.handleReject,
	} {
		if id, ok := strings.CutSuffix(rest, suffix); ok {
			if r.Method != http.MethodPost {
				http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			handle(w, r, id)
			return
		}
	}

	id := rest
	switch r.Method {
	case http.MethodGet:
		s.handleGetSession(w, r, id)
	case http.MethodDelete:
		s.handleTerminate(w, r, id)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleGetSession answers a read of one session (ADR-0019). The caller is the one the
// Gateway verified (callerId) with the roles of that token (actorRoles, comma-separated
// like the list's): the Gateway builds this query itself, and only an internal caller can
// reach it (ADR-0010). The refusal says nothing of the session: not its account, not its
// requester.
func (s *HTTPServer) handleGetSession(w http.ResponseWriter, r *http.Request, sessionID string) {
	q := r.URL.Query()
	var roles []string
	if raw := q.Get("actorRoles"); raw != "" {
		roles = strings.Split(raw, ",")
	}
	sess, err := s.svc.GetSession(r.Context(), sessionID, q.Get("callerId"), roles)
	switch {
	case err == nil:
	case errors.Is(err, domain.ErrNotFound):
		http.Error(w, "session not found", http.StatusNotFound)
		return
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	default:
		// A dependency did not answer; the cause stays in this process's log.
		log.Printf("session-broker: reading session %s not done: %v", sessionID, err)
		http.Error(w, "the session could not be read: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
}

// terminateRequest is what the Gateway sends: who is asking, and with which roles, from
// the verified token (ADR-0017). Without a caller — or with a body that is not this —
// there is nothing to end a session on behalf of.
type terminateRequest struct {
	CallerID   string   `json:"callerId"`
	ActorRoles []string `json:"actorRoles"`
}

func (s *HTTPServer) handleTerminate(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req terminateRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		// No body, or not JSON: no caller. Refused like any caller who has no authority,
		// not described (as for connect).
		req = terminateRequest{}
	}
	sess, err := s.svc.TerminateSession(r.Context(), sessionID, req.CallerID, req.ActorRoles)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
	case errors.Is(err, domain.ErrNotFound):
		http.Error(w, "session not found", http.StatusNotFound)
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, domain.ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		// A dependency did not answer. Nothing was ended; the cause stays in this
		// process's log, not in what a client reads (it can name an address).
		log.Printf("session-broker: termination of %s not made: %v", sessionID, err)
		http.Error(w, "the session was not ended: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
	}
}

// -- POST /sessions/{id}/connect (mirrors docs/api/rest/openapi.yaml, ConnectionTicket) --

type connectionTicketResponse struct {
	ProxyEndpoint string    `json:"proxyEndpoint"`
	Ticket        string    `json:"ticket"`
	Protocol      string    `json:"protocol"`
	ExpiresAt     time.Time `json:"expiresAt"`
}

// connectRequest is what the Gateway sends: who is asking, from the verified token.
// Without it — or with anyone but the session's requester — there is no ticket.
type connectRequest struct {
	CallerID string `json:"callerId"`
}

func (s *HTTPServer) handleConnect(w http.ResponseWriter, r *http.Request, sessionID string) {
	var req connectRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		// No body, or not JSON: no caller. Refused like any caller who is not the
		// requester, not described.
		req = connectRequest{}
	}
	proxyEndpoint, ticket, protocol, expiresAt, err := s.svc.ConnectDetails(r.Context(), sessionID, req.CallerID)
	if err != nil {
		switch {
		case errors.Is(err, domain.ErrForbidden):
			http.Error(w, err.Error(), http.StatusForbidden)
		case errors.Is(err, domain.ErrRecordingUnavailable):
			// Not a conflict with the session: the platform cannot record it
			// right now. The reason is generic on purpose; the proxy logs the cause.
			http.Error(w, "recording unavailable: the session was not started, try again shortly", http.StatusServiceUnavailable)
		case errors.Is(err, domain.ErrNotFound):
			http.Error(w, "session not found", http.StatusNotFound)
		case errors.Is(err, domain.ErrAccountNotPinned):
			// The account must be pinned first (ADR-0039): the operator is told, by the
			// Vault's code, not its text (ADR-0042).
			http.Error(w, domain.ErrAccountNotPinned.Error(), http.StatusConflict)
		case errors.Is(err, domain.ErrAccountTLSNotPinned):
			http.Error(w, domain.ErrAccountTLSNotPinned.Error(), http.StatusConflict)
		case errors.Is(err, domain.ErrUnsupportedProtocol):
			http.Error(w, domain.ErrUnsupportedProtocol.Error(), http.StatusConflict)
		case errors.Is(err, domain.ErrConflict):
			http.Error(w, err.Error(), http.StatusConflict)
		default:
			// The Vault, the proxy or the network did not answer as they should. Nothing was
			// started; the cause stays in this process's log, not in what a client reads (it
			// can name an address).
			log.Printf("session-broker: connection to %s not started: %v", sessionID, err)
			http.Error(w, "the session was not started: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
		}
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(connectionTicketResponse{ProxyEndpoint: proxyEndpoint, Ticket: ticket, Protocol: protocol, ExpiresAt: expiresAt})
}

// -- POST /sessions/{id}/approve, POST /sessions/{id}/reject (ADR-0011) -------

// decisionRequest is what the Gateway sends: the verified user and the roles of the
// verified token. Whatever the client put in its own body never gets this far.
type decisionRequest struct {
	DecidedBy  string   `json:"decidedBy"`
	ActorRoles []string `json:"actorRoles"`
}

func (s *HTTPServer) handleApprove(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.decide(w, r, sessionID, s.svc.ApproveBreakGlass)
}

func (s *HTTPServer) handleReject(w http.ResponseWriter, r *http.Request, sessionID string) {
	s.decide(w, r, sessionID, s.svc.RejectBreakGlass)
}

func (s *HTTPServer) decide(w http.ResponseWriter, r *http.Request, sessionID string,
	decide func(ctx context.Context, sessionID, decidedBy string, roles []string) (*domain.Session, error)) {
	var req decisionRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "invalid decision request", http.StatusBadRequest)
		return
	}
	sess, err := decide(r.Context(), sessionID, req.DecidedBy, req.ActorRoles)
	switch {
	case err == nil:
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(toSessionResponse(sess))
	case errors.Is(err, domain.ErrNotFound):
		http.Error(w, "session not found", http.StatusNotFound)
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, domain.ErrConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		// A dependency did not answer. The decision was not taken; the cause stays
		// in this process's log, not in what a client reads (it can name an address).
		log.Printf("session-broker: decision on %s not taken: %v", sessionID, err)
		http.Error(w, "the decision was not taken: a dependency is unavailable, try again shortly", http.StatusServiceUnavailable)
	}
}

type sessionSearchResponse struct {
	Sessions []sessionResponse `json:"sessions"`
	// Next is the cursor of the next page; empty when there is none.
	Next string `json:"next"`
}

// encodeCursor and decodeCursor make a position opaque to the client: base64url of the
// creation time (RFC 3339, nanoseconds) and the id.
func encodeCursor(c *domain.SearchCursor) string {
	if c == nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString([]byte(c.CreatedAt.UTC().Format(time.RFC3339Nano) + "|" + c.ID))
}

func decodeCursor(s string) (*domain.SearchCursor, error) {
	if s == "" {
		return nil, nil
	}
	raw, err := base64.RawURLEncoding.DecodeString(s)
	if err != nil {
		return nil, err
	}
	at, id, ok := strings.Cut(string(raw), "|")
	t, err := time.Parse(time.RFC3339Nano, at)
	if !ok || err != nil || id == "" {
		return nil, errors.New("not a cursor")
	}
	return &domain.SearchCursor{CreatedAt: t, ID: id}, nil
}

// handleSearch is GET /sessions/search (ADR-0080): the search from the client, callerId and
// actorRoles from the Gateway.
func (s *HTTPServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	from, errFrom := time.Parse(time.RFC3339, q.Get("from"))
	to, errTo := time.Parse(time.RFC3339, q.Get("to"))
	after, errCursor := decodeCursor(q.Get("cursor"))
	if errFrom != nil || errTo != nil || errCursor != nil {
		http.Error(w, "from and to are RFC 3339 times, and cursor is the one a page gave", http.StatusBadRequest)
		return
	}
	req := application.SessionSearchRequest{SessionSearch: domain.SessionSearch{
		Text: q.Get("q"), From: from, To: to, After: after,
		Protocol: q.Get("protocol"), RequestedBy: q.Get("requestedBy"), PrivilegedAccountID: q.Get("privilegedAccountId"),
	}, Status: domain.SessionStatus(q.Get("status"))}
	switch q.Get("breakGlass") {
	case "":
	case "true", "false":
		v := q.Get("breakGlass") == "true"
		req.BreakGlass = &v
	default:
		http.Error(w, "breakGlass is true or false", http.StatusBadRequest)
		return
	}
	var roles []string
	if v := q.Get("actorRoles"); v != "" {
		roles = strings.Split(v, ",")
	}
	callerID := q.Get("callerId")
	result, err := s.svc.SearchSessions(r.Context(), callerID, roles, req)
	switch {
	case err == nil:
	case errors.Is(err, application.ErrInvalidSearch):
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	case errors.Is(err, domain.ErrForbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	default:
		// Never the text searched, nor the cause: the Gateway relays this body.
		log.Printf("session-broker: a search of sessions for user %s not done: %v", callerID, err)
		http.Error(w, http.StatusText(http.StatusServiceUnavailable), http.StatusServiceUnavailable)
		return
	}
	out := sessionSearchResponse{Sessions: make([]sessionResponse, 0, len(result.Sessions)), Next: encodeCursor(result.Next)}
	for _, sess := range result.Sessions {
		out.Sessions = append(out.Sessions, toSessionResponse(sess))
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

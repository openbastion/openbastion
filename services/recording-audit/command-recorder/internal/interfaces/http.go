// Package interfaces exposes the Command Recorder over JSON/HTTP.
//
// SANDBOX NOTE: this project's internal transport is specified as gRPC
// (proto/recording/v1/recording.proto). google.golang.org/grpc could not be
// fetched in this build sandbox — see /NOTES_SANDBOX.md. This layer carries
// the same shapes: POST /recorder/v1/command-entries takes a batch of
// SessionRecording.CommandEntry and answers with StreamAck's
// entries_received, field for field, so generated gRPC code can replace it
// without touching internal/application or internal/domain.
package interfaces

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
)

// maxBodyBytes bounds a request body: a full batch of maximum-size commands
// is about 8 MiB, so 16 MiB leaves JSON overhead without being unlimited.
const maxBodyBytes = 16 << 20

type HTTPServer struct {
	svc *application.RecorderService
}

func NewHTTPServer(svc *application.RecorderService) *HTTPServer {
	return &HTTPServer{svc: svc}
}

func (s *HTTPServer) Routes() *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/recorder/v1/command-entries", s.handleRecord)
	mux.HandleFunc("/recorder/v1/sessions/", s.handleSession)
	mux.HandleFunc("/recorder/v1/search", s.handleSearch)
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/readyz", s.handleReady)
	return mux
}

// -- GET /readyz --------------------------------------------------------------
//
// Liveness (/healthz) says the process runs. Readiness says it could record a
// session now. Proxies required to record ask this before admitting a session
// (ADR-0008), so it must be false whenever a write would fail.
func (s *HTTPServer) handleReady(w http.ResponseWriter, r *http.Request) {
	if err := s.svc.Ready(r.Context()); err != nil {
		// The reason stays in the log: this endpoint is reachable by every
		// proxy, and a database error can carry addresses and schema names.
		log.Printf("command-recorder: not ready: %v", err)
		http.Error(w, "not ready", http.StatusServiceUnavailable)
		return
	}
	w.WriteHeader(http.StatusOK)
}

// -- POST /recorder/v1/command-entries (SessionRecording.StreamCommandEntries) --

type commandEntryRequest struct {
	SessionID string    `json:"session_id"`
	Timestamp time.Time `json:"ts"`
	Command   string    `json:"command"`
}

type recordRequest struct {
	Entries []commandEntryRequest `json:"entries"`
}

type recordResponse struct {
	EntriesReceived int `json:"entries_received"`
}

func (s *HTTPServer) handleRecord(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req recordRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBodyBytes)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entries := make([]domain.CommandEntry, 0, len(req.Entries))
	for _, e := range req.Entries {
		entries = append(entries, domain.CommandEntry{SessionID: e.SessionID, Timestamp: e.Timestamp, Command: e.Command})
	}
	n, err := s.svc.Record(r.Context(), entries)
	if err != nil {
		http.Error(w, err.Error(), statusFor(err))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	_ = json.NewEncoder(w).Encode(recordResponse{EntriesReceived: n})
}

// -- GET /recorder/v1/sessions/{id}/commands (mirrors GET /sessions/{id}/recording, docs/api/rest/openapi.yaml) --

type recordedCommand struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
}

type recordingResponse struct {
	SessionID    string            `json:"sessionId"`
	Entries      []recordedCommand `json:"entries"`
	Page         int               `json:"page"`
	PageSize     int               `json:"pageSize"`
	TotalEntries int               `json:"totalEntries"`
}

func (s *HTTPServer) handleSession(w http.ResponseWriter, r *http.Request) {
	rest := strings.TrimPrefix(r.URL.Path, "/recorder/v1/sessions/")
	sessionID, ok := strings.CutSuffix(rest, "/commands")
	if !ok || sessionID == "" || strings.Contains(sessionID, "/") {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	q := r.URL.Query()
	// A missing or unparsable value becomes 0, which ClampPage turns into the default.
	page, _ := strconv.Atoi(q.Get("page"))
	pageSize, _ := strconv.Atoi(q.Get("pageSize"))
	// Who reads, and with which roles, are the Gateway's: only the Gateway may call this
	// route (CallerRules), and it builds both from the verified token (ADR-0022).
	callerID := q.Get("callerId")
	actorRoles := splitCommaList(q.Get("actorRoles"))

	entries, total, err := s.svc.GetRecording(r.Context(), callerID, actorRoles, sessionID, page, pageSize)
	if err != nil {
		status := statusFor(err)
		if status == http.StatusForbidden || status == http.StatusBadRequest {
			http.Error(w, err.Error(), status)
			return
		}
		// A dependency or the store failed: the Gateway relays this body to the client, so it
		// says nothing of the session, of the recording or of the failure — the cause, which
		// can name addresses and tables, stays in this log.
		log.Printf("command-recorder: reading the recording of session %s for user %s not done: %v", sessionID, callerID, err)
		http.Error(w, http.StatusText(status), status)
		return
	}

	page, pageSize = application.ClampPage(page, pageSize)
	out := recordingResponse{SessionID: sessionID, Entries: make([]recordedCommand, 0, len(entries)), Page: page, PageSize: pageSize, TotalEntries: total}
	for _, e := range entries {
		out.Entries = append(out.Entries, recordedCommand{Timestamp: e.Timestamp, Command: e.Command})
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(out)
}

// statusFor maps an application error onto an HTTP status. A dependency that
// did not answer (Authorization, or the audit a read must be written to) is a
// 503; anything else that is neither a refused batch nor a refused read is the
// store failing — a 500. Neither is a 403: calling an outage "forbidden" would
// hide it.
func statusFor(err error) int {
	switch {
	case errors.Is(err, domain.ErrInvalidEntry), errors.Is(err, domain.ErrNotASessionID), errors.Is(err, application.ErrInvalidSearch):
		return http.StatusBadRequest
	case errors.Is(err, domain.ErrForbidden):
		return http.StatusForbidden
	case errors.Is(err, domain.ErrUnavailable):
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
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

type searchHit struct {
	Timestamp time.Time `json:"timestamp"`
	Command   string    `json:"command"`
}

type searchSession struct {
	SessionID string      `json:"sessionId"`
	Hits      []searchHit `json:"hits"`
}

type searchResponse struct {
	SearchID  string          `json:"searchId"`
	Sessions  []searchSession `json:"sessions"`
	Truncated bool            `json:"truncated"`
}

// handleSearch is GET /recorder/v1/search (ADR-0080): q, from and to (RFC 3339) from the client,
// callerId and actorRoles from the Gateway.
func (s *HTTPServer) handleSearch(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	q := r.URL.Query()
	from, errFrom := time.Parse(time.RFC3339, q.Get("from"))
	to, errTo := time.Parse(time.RFC3339, q.Get("to"))
	if errFrom != nil || errTo != nil {
		http.Error(w, "from and to are RFC 3339 times", http.StatusBadRequest)
		return
	}
	callerID := q.Get("callerId")
	result, err := s.svc.Search(r.Context(), callerID, splitCommaList(q.Get("actorRoles")), q.Get("q"), from, to)
	if err != nil {
		switch {
		case errors.Is(err, application.ErrSearchDisabled):
			http.NotFound(w, r)
		case errors.Is(err, application.ErrInvalidSearch), errors.Is(err, domain.ErrForbidden):
			http.Error(w, err.Error(), statusFor(err))
		default:
			// Never the text searched, nor the cause: the Gateway relays this body.
			log.Printf("command-recorder: a search for user %s not done: %v", callerID, err)
			status := statusFor(err)
			http.Error(w, http.StatusText(status), status)
		}
		return
	}
	out := searchResponse{SearchID: result.SearchID, Sessions: make([]searchSession, 0, len(result.Sessions)), Truncated: result.Truncated}
	for _, found := range result.Sessions {
		ss := searchSession{SessionID: found.SessionID, Hits: make([]searchHit, 0, len(found.Hits))}
		for _, h := range found.Hits {
			ss.Hits = append(ss.Hits, searchHit{Timestamp: h.Timestamp, Command: h.Command})
		}
		out.Sessions = append(out.Sessions, ss)
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(out)
}

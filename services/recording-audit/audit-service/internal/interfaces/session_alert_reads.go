package interfaces

import (
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
)

const maxSessionAlertQueryBytes = 4096

type sessionAlertResponse struct {
	ID                     string               `json:"id"`
	RuleID                 string               `json:"rule_id"`
	RuleVersion            string               `json:"rule_version"`
	SourceEventID          string               `json:"source_event_id"`
	SessionID              string               `json:"session_id"`
	Severity               domain.AlertSeverity `json:"severity"`
	Status                 string               `json:"status"`
	Summary                string               `json:"summary"`
	DetectedAt             time.Time            `json:"detected_at"`
	CreatedAt              time.Time            `json:"created_at"`
	Revision               int64                `json:"revision"`
	AcknowledgedAt         *time.Time           `json:"acknowledged_at,omitempty"`
	AcknowledgedBy         string               `json:"acknowledged_by,omitempty"`
	AcknowledgementEventID string               `json:"acknowledgement_event_id,omitempty"`
}

type sessionAlertPageResponse struct {
	Alerts     []sessionAlertResponse `json:"alerts"`
	NextCursor string                 `json:"next_cursor,omitempty"`
	HasMore    bool                   `json:"has_more"`
}

func (s *HTTPServer) handleSessionAlertList(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if len(r.URL.RawQuery) > maxSessionAlertQueryBytes {
		http.Error(w, "query too large", http.StatusRequestURITooLong)
		return
	}
	allowed := map[string]bool{"status": true, "severity": true, "session_id": true, "since": true, "until": true, "cursor": true, "limit": true}
	values, err := url.ParseQuery(r.URL.RawQuery)
	if err != nil {
		http.Error(w, "invalid session alert query", http.StatusBadRequest)
		return
	}
	for key, items := range values {
		if !allowed[key] || len(items) != 1 || items[0] == "" {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
	}
	query := application.SessionAlertListQuery{
		Status: values.Get("status"), Severity: values.Get("severity"), SessionID: values.Get("session_id"), Cursor: values.Get("cursor"),
	}
	if raw := values.Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		query.Limit = limit
	}
	for name, target := range map[string]**time.Time{"since": &query.Since, "until": &query.Until} {
		if raw := values.Get(name); raw != "" {
			parsed, err := time.Parse(time.RFC3339Nano, raw)
			if err != nil {
				http.Error(w, "invalid session alert query", http.StatusBadRequest)
				return
			}
			utc := parsed.UTC()
			*target = &utc
		}
	}
	page, err := s.svc.ListSessionAlerts(r.Context(), query)
	if err != nil {
		if errors.Is(err, application.ErrInvalidSessionAlertQuery) {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		log.Printf("audit-service: session alert list unavailable: %v", err)
		http.Error(w, "session alert list unavailable", http.StatusServiceUnavailable)
		return
	}
	response := sessionAlertPageResponse{Alerts: make([]sessionAlertResponse, 0, len(page.Alerts)), NextCursor: page.NextCursor, HasMore: page.HasMore}
	for _, alert := range page.Alerts {
		response.Alerts = append(response.Alerts, toSessionAlertResponse(alert))
	}
	writeSessionAlertJSON(w, response)
}

func (s *HTTPServer) handleSessionAlertSummary(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" {
		http.Error(w, "unsupported query parameter", http.StatusBadRequest)
		return
	}
	summary, err := s.svc.SessionAlertSummary(r.Context())
	if err != nil {
		log.Printf("audit-service: session alert summary unavailable: %v", err)
		http.Error(w, "session alert summary unavailable", http.StatusServiceUnavailable)
		return
	}
	writeSessionAlertJSON(w, summary)
}

func (s *HTTPServer) handleSessionAlertDetail(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.RawQuery != "" || strings.Contains(strings.TrimPrefix(r.URL.Path, "/audit/v1/session-alerts/"), "/") {
		http.Error(w, "invalid session alert id", http.StatusBadRequest)
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/audit/v1/session-alerts/")
	alert, err := s.svc.GetSessionAlert(r.Context(), id)
	if errors.Is(err, application.ErrInvalidSessionAlertQuery) {
		http.Error(w, "invalid session alert id", http.StatusBadRequest)
		return
	}
	if errors.Is(err, application.ErrSessionAlertNotFound) {
		http.Error(w, "session alert not found", http.StatusNotFound)
		return
	}
	if err != nil {
		log.Printf("audit-service: session alert detail unavailable: %v", err)
		http.Error(w, "session alert detail unavailable", http.StatusServiceUnavailable)
		return
	}
	writeSessionAlertJSON(w, toSessionAlertResponse(*alert))
}

func toSessionAlertResponse(alert domain.SessionAlert) sessionAlertResponse {
	return sessionAlertResponse{
		ID: alert.ID, RuleID: alert.RuleID, RuleVersion: alert.RuleVersion, SourceEventID: alert.SourceEventID,
		SessionID: alert.SessionID, Severity: alert.Severity, Status: alert.Status, Summary: alert.Summary,
		DetectedAt: alert.DetectedAt.UTC(), CreatedAt: alert.CreatedAt.UTC(), Revision: alert.Revision,
		AcknowledgedAt: alert.AcknowledgedAt, AcknowledgedBy: alert.AcknowledgedBy, AcknowledgementEventID: alert.AcknowledgementEventID,
	}
}

func writeSessionAlertJSON(w http.ResponseWriter, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	_ = json.NewEncoder(w).Encode(value)
}

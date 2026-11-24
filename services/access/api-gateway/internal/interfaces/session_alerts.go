package interfaces

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	neturl "net/url"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	sessionAlertsResourceAll       = "session-alerts:all"
	sessionAlertsReadAction        = "session-alerts:read"
	sessionAlertsAcknowledgeAction = "session-alerts:acknowledge"
	maxSessionAlertsResponse       = 1 << 20
	maxSessionAlertsQuery          = 4 << 10
)

type sessionAlertAccessRequest struct {
	ActorRoles []string `json:"actor_roles"`
	Resource   string   `json:"resource"`
	Action     string   `json:"action"`
}

type sessionAlertAccessResponse struct {
	Allowed          bool   `json:"allowed"`
	RequiresApproval bool   `json:"requires_approval"`
	DecisionReason   string `json:"decision_reason"`
}

type publicSessionAlert struct {
	ID                     string     `json:"id"`
	RuleID                 string     `json:"rule_id"`
	RuleVersion            string     `json:"rule_version"`
	SourceEventID          string     `json:"source_event_id"`
	SessionID              string     `json:"session_id"`
	Severity               string     `json:"severity"`
	Status                 string     `json:"status"`
	Summary                string     `json:"summary"`
	DetectedAt             time.Time  `json:"detected_at"`
	CreatedAt              time.Time  `json:"created_at"`
	Revision               int64      `json:"revision"`
	AcknowledgedAt         *time.Time `json:"acknowledged_at,omitempty"`
	AcknowledgedBy         string     `json:"acknowledged_by,omitempty"`
	AcknowledgementEventID string     `json:"acknowledgement_event_id,omitempty"`
}

type publicSessionAlertPage struct {
	Alerts     []publicSessionAlert `json:"alerts"`
	NextCursor string               `json:"next_cursor,omitempty"`
	HasMore    *bool                `json:"has_more"`
}

type publicSessionAlertAcknowledgement struct {
	ID                     string     `json:"id"`
	Status                 string     `json:"status"`
	Revision               int64      `json:"revision"`
	AcknowledgedAt         *time.Time `json:"acknowledged_at"`
	AcknowledgedBy         string     `json:"acknowledged_by"`
	AcknowledgementEventID string     `json:"acknowledgement_event_id"`
}

type sessionAlertAcknowledgementRequestBody struct {
	ExpectedRevision int64 `json:"expected_revision"`
}

type internalSessionAlertAcknowledgementRequest struct {
	ActorID          string `json:"actor_id"`
	ExpectedRevision int64  `json:"expected_revision"`
}

type publicSessionAlertSummary struct {
	UnacknowledgedCount *int64           `json:"unacknowledged_count"`
	BySeverity          map[string]int64 `json:"by_severity"`
	AsOf                time.Time        `json:"as_of"`
	Durable             *bool            `json:"durable"`
}

// handleSessionAlerts is the only public route to the operator alert projection.
// The Gateway verifies the end-user token, checks the dedicated ABAC permission,
// then calls the private Audit Service using its own mTLS workload identity.
func (g *GatewayServer) handleSessionAlerts(w http.ResponseWriter, r *http.Request, id identity) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	path := strings.TrimPrefix(r.URL.EscapedPath(), "/session-alerts")
	if path == "/" {
		path = ""
	}
	resource := sessionAlertsResourceAll
	upstreamPath := "/audit/v1/session-alerts"
	forwardedQuery := ""
	switch {
	case path == "":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !sessionAlertRequestHasNoBody(w, r) {
			return
		}
		if len(r.URL.RawQuery) > maxSessionAlertsQuery {
			http.Error(w, "query too large", http.StatusRequestURITooLong)
			return
		}
		values, err := neturl.ParseQuery(r.URL.RawQuery)
		if err != nil {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		for key, items := range values {
			if !allowedSessionAlertQueryKey(key) || len(items) != 1 || items[0] == "" {
				http.Error(w, "invalid session alert query", http.StatusBadRequest)
				return
			}
		}
		if status := values.Get("status"); status != "" && status != "unacknowledged" && status != "acknowledged" {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		switch values.Get("severity") {
		case "", "info", "low", "medium", "high", "critical":
		default:
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		if sessionID := values.Get("session_id"); len(sessionID) > 256 || strings.IndexFunc(sessionID, unicode.IsControl) >= 0 {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		if cursor := values.Get("cursor"); cursor != "" && !validSessionAlertCursor(cursor) {
			http.Error(w, "invalid session alert query", http.StatusBadRequest)
			return
		}
		if raw := values.Get("limit"); raw != "" {
			n, err := strconv.Atoi(raw)
			if err != nil || n < 1 || n > 100 {
				http.Error(w, "invalid session alert query", http.StatusBadRequest)
				return
			}
		}
		for _, key := range []string{"since", "until"} {
			if raw := values.Get(key); raw != "" {
				if _, err := time.Parse(time.RFC3339Nano, raw); err != nil {
					http.Error(w, "invalid session alert query", http.StatusBadRequest)
					return
				}
			}
		}
		if since, until := values.Get("since"), values.Get("until"); since != "" && until != "" {
			a, _ := time.Parse(time.RFC3339Nano, since)
			b, _ := time.Parse(time.RFC3339Nano, until)
			if b.Before(a) {
				http.Error(w, "invalid session alert query", http.StatusBadRequest)
				return
			}
		}
		forwardedQuery = values.Encode()
	case path == "/summary":
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !sessionAlertRequestHasNoBody(w, r) {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "unsupported session alert query", http.StatusBadRequest)
			return
		}
		upstreamPath += "/summary"
	case strings.HasPrefix(path, "/") && strings.HasSuffix(path, "/acknowledge") && strings.Count(path, "/") == 2:
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "unsupported session alert query", http.StatusBadRequest)
			return
		}
		alertIDRaw := strings.TrimSuffix(strings.TrimPrefix(path, "/"), "/acknowledge")
		alertID, err := neturl.PathUnescape(alertIDRaw)
		if err != nil || !validSessionAlertID(alertID) {
			http.Error(w, "invalid session alert id", http.StatusBadRequest)
			return
		}
		// Every acknowledgement can append an audit event. Charge the verified user's
		// shared write-action budget before parsing or forwarding (ADR-0016).
		if !g.admitSessionAction(w, id) {
			return
		}
		var body sessionAlertAcknowledgementRequestBody
		decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&body); err != nil {
			var tooBig *http.MaxBytesError
			if errors.As(err, &tooBig) {
				http.Error(w, "acknowledgement request too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "invalid acknowledgement request", http.StatusBadRequest)
			}
			return
		}
		var extra any
		if err := decoder.Decode(&extra); err != io.EOF || body.ExpectedRevision < 1 {
			http.Error(w, "invalid acknowledgement request", http.StatusBadRequest)
			return
		}
		resource = "session-alerts:" + alertID
		if id.UserID == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		decision, err := g.checkSessionAlertAccess(r.Context(), id.Roles, resource, sessionAlertsAcknowledgeAction)
		if err != nil {
			http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
			return
		}
		if !decision.Allowed || decision.RequiresApproval {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if g.auditURL == "" {
			http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
			return
		}
		internalBody, err := json.Marshal(internalSessionAlertAcknowledgementRequest{ActorID: id.UserID, ExpectedRevision: body.ExpectedRevision})
		if err != nil {
			http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
			return
		}
		upstreamPath = "/audit/v1/session-alerts/" + neturl.PathEscape(alertID) + "/acknowledge"
		ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.auditURL+upstreamPath, bytes.NewReader(internalBody))
		if err != nil {
			http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
			return
		}
		req.Header.Set("Content-Type", "application/json")
		resp, err := g.doSessionAlertRequest(req)
		if err != nil {
			if r.Context().Err() == nil {
				http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
			}
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			status := resp.StatusCode
			if status >= 500 {
				status = http.StatusServiceUnavailable
			}
			if status != http.StatusBadRequest && status != http.StatusNotFound && status != http.StatusConflict && status != http.StatusServiceUnavailable {
				status = http.StatusBadGateway
			}
			http.Error(w, http.StatusText(status), status)
			return
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, (16<<10)+1))
		if err != nil || len(data) > 16<<10 {
			http.Error(w, "session alerts unavailable", http.StatusBadGateway)
			return
		}
		var acknowledgement publicSessionAlertAcknowledgement
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&acknowledgement); err != nil {
			http.Error(w, "session alerts unavailable", http.StatusBadGateway)
			return
		}
		var trailing any
		if err := dec.Decode(&trailing); err != io.EOF || acknowledgement.ID != alertID || acknowledgement.Status != "acknowledged" || acknowledgement.Revision < 2 || acknowledgement.AcknowledgedAt == nil || acknowledgement.AcknowledgedAt.IsZero() || acknowledgement.AcknowledgedBy == "" || acknowledgement.AcknowledgementEventID == "" || len(acknowledgement.AcknowledgementEventID) > 256 || strings.IndexFunc(acknowledgement.AcknowledgementEventID, unicode.IsControl) >= 0 {
			http.Error(w, "session alerts unavailable", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(acknowledgement)
		return
	case strings.HasPrefix(path, "/") && !strings.Contains(strings.TrimPrefix(path, "/"), "/"):
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !sessionAlertRequestHasNoBody(w, r) {
			return
		}
		if r.URL.RawQuery != "" {
			http.Error(w, "unsupported session alert query", http.StatusBadRequest)
			return
		}
		alertID, err := neturl.PathUnescape(strings.TrimPrefix(path, "/"))
		if err != nil || !validSessionAlertID(alertID) {
			http.Error(w, "invalid session alert id", http.StatusBadRequest)
			return
		}
		resource = "session-alerts:" + alertID
		upstreamPath += "/" + neturl.PathEscape(alertID)
	default:
		http.NotFound(w, r)
		return
	}

	decision, err := g.checkSessionAlertAccess(r.Context(), id.Roles, resource, sessionAlertsReadAction)
	if err != nil {
		http.Error(w, "authorization unavailable", http.StatusServiceUnavailable)
		return
	}
	if !decision.Allowed || decision.RequiresApproval {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if g.auditURL == "" {
		http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
		return
	}
	if forwardedQuery != "" {
		upstreamPath += "?" + forwardedQuery
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.auditURL+upstreamPath, nil)
	if err != nil {
		http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
		return
	}
	resp, err := g.doSessionAlertRequest(req)
	if err != nil {
		if r.Context().Err() == nil {
			http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
		}
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 500 {
		http.Error(w, "session alerts unavailable", http.StatusServiceUnavailable)
		return
	}
	if resp.StatusCode != http.StatusOK {
		status := resp.StatusCode
		if status != http.StatusBadRequest && status != http.StatusNotFound {
			status = http.StatusBadGateway
		}
		http.Error(w, http.StatusText(status), status)
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxSessionAlertsResponse+1))
	if err != nil || len(data) > maxSessionAlertsResponse {
		http.Error(w, "session alerts unavailable", http.StatusBadGateway)
		return
	}
	public, err := validateSessionAlertResponse(data, path)
	if err != nil {
		http.Error(w, "session alerts unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(public)
}

func sessionAlertRequestHasNoBody(w http.ResponseWriter, r *http.Request) bool {
	if r.Body == nil || r.Body == http.NoBody {
		return true
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 1))
	if err != nil || len(body) != 0 {
		http.Error(w, "session alert reads do not accept a body", http.StatusBadRequest)
		return false
	}
	return true
}

func (g *GatewayServer) doSessionAlertRequest(req *http.Request) (*http.Response, error) {
	client := g.httpClient
	if client == nil {
		client = http.DefaultClient
	}
	// A redirect from an internal peer must never make the Gateway send its mTLS
	// client identity or an operator request to a different destination.
	redirectFree := *client
	redirectFree.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	return redirectFree.Do(req)
}

func (g *GatewayServer) checkSessionAlertAccess(ctx context.Context, roles []string, resource, action string) (sessionAlertAccessResponse, error) {
	if g.authorizationURL == "" || g.httpClient == nil {
		return sessionAlertAccessResponse{}, errors.New("authorization unavailable")
	}
	body, err := json.Marshal(sessionAlertAccessRequest{ActorRoles: roles, Resource: resource, Action: action})
	if err != nil {
		return sessionAlertAccessResponse{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.authorizationURL+"/authz/v1/check-access", bytes.NewReader(body))
	if err != nil {
		return sessionAlertAccessResponse{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.doSessionAlertRequest(req)
	if err != nil {
		return sessionAlertAccessResponse{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return sessionAlertAccessResponse{}, errors.New("authorization decision unavailable")
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, (4<<10)+1))
	if err != nil || len(data) > 4<<10 {
		return sessionAlertAccessResponse{}, errors.New("invalid authorization response bounds")
	}
	var decision sessionAlertAccessResponse
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&decision); err != nil {
		return sessionAlertAccessResponse{}, err
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return sessionAlertAccessResponse{}, errors.New("invalid authorization response")
	}
	return decision, nil
}

func validSessionAlertID(value string) bool {
	if len(value) != len("alert_")+32 || !strings.HasPrefix(value, "alert_") {
		return false
	}
	for _, c := range value[len("alert_"):] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func validSessionAlertCursor(cursor string) bool {
	if len(cursor) > 256 {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(cursor)
	if err != nil {
		return false
	}
	parts := strings.Split(string(raw), "|")
	if len(parts) != 2 || !validSessionAlertID(parts[1]) {
		return false
	}
	_, err = time.Parse(time.RFC3339Nano, parts[0])
	return err == nil
}

func allowedSessionAlertQueryKey(key string) bool {
	switch key {
	case "status", "severity", "session_id", "since", "until", "cursor", "limit":
		return true
	default:
		return false
	}
}

// validateSessionAlertResponse treats even the mTLS upstream as untrusted data:
// only the documented DTO is allowed across the public Gateway boundary.
func validateSessionAlertResponse(data []byte, route string) ([]byte, error) {
	decode := func(target any) error {
		dec := json.NewDecoder(bytes.NewReader(data))
		dec.DisallowUnknownFields()
		if err := dec.Decode(target); err != nil {
			return err
		}
		var extra any
		if err := dec.Decode(&extra); err != io.EOF {
			return errors.New("trailing session alert response data")
		}
		return nil
	}
	validAlert := func(alert publicSessionAlert) bool {
		if !validSessionAlertID(alert.ID) || alert.RuleID == "" || alert.RuleVersion == "" || alert.SourceEventID == "" ||
			alert.SessionID == "" || len(alert.SessionID) > 256 || alert.Summary == "" || len(alert.Summary) > 512 ||
			alert.DetectedAt.IsZero() || alert.CreatedAt.IsZero() || alert.Revision < 1 {
			return false
		}
		for _, r := range alert.SessionID {
			if unicode.IsControl(r) {
				return false
			}
		}
		switch alert.Severity {
		case "info", "low", "medium", "high", "critical":
		default:
			return false
		}
		switch alert.Status {
		case "unacknowledged":
			return alert.AcknowledgedAt == nil && alert.AcknowledgedBy == "" && alert.AcknowledgementEventID == ""
		case "acknowledged":
			return alert.AcknowledgedAt != nil && !alert.AcknowledgedAt.IsZero() && alert.AcknowledgedBy != "" && alert.AcknowledgementEventID != ""
		default:
			return false
		}
	}
	if route == "" {
		var page publicSessionAlertPage
		if err := decode(&page); err != nil {
			return nil, err
		}
		if page.Alerts == nil || page.HasMore == nil || len(page.Alerts) > 100 || (*page.HasMore && !validSessionAlertCursor(page.NextCursor)) || (!*page.HasMore && page.NextCursor != "") {
			return nil, errors.New("invalid session alert page bounds")
		}
		for _, alert := range page.Alerts {
			if !validAlert(alert) {
				return nil, errors.New("invalid session alert item")
			}
		}
		return json.Marshal(page)
	}
	if route == "/summary" {
		var summary publicSessionAlertSummary
		if err := decode(&summary); err != nil {
			return nil, err
		}
		if len(summary.BySeverity) != 5 {
			return nil, errors.New("incomplete session alert summary")
		}
		counts := []int64{summary.BySeverity["info"], summary.BySeverity["low"], summary.BySeverity["medium"], summary.BySeverity["high"], summary.BySeverity["critical"]}
		for _, severity := range []string{"info", "low", "medium", "high", "critical"} {
			if _, ok := summary.BySeverity[severity]; !ok {
				return nil, errors.New("incomplete session alert summary")
			}
		}
		var total int64
		for _, count := range counts {
			if count < 0 || total > math.MaxInt64-count {
				return nil, errors.New("invalid session alert count")
			}
			total += count
		}
		if summary.UnacknowledgedCount == nil || summary.Durable == nil || *summary.UnacknowledgedCount < 0 || total != *summary.UnacknowledgedCount || summary.AsOf.IsZero() {
			return nil, errors.New("inconsistent session alert summary")
		}
		return json.Marshal(summary)
	}
	var alert publicSessionAlert
	if err := decode(&alert); err != nil {
		return nil, err
	}
	if !validAlert(alert) {
		return nil, errors.New("invalid session alert detail")
	}
	return json.Marshal(alert)
}

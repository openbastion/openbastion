package interfaces_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

type alertAuthzCall struct {
	Roles    []string `json:"actor_roles"`
	Resource string   `json:"resource"`
	Action   string   `json:"action"`
}

func alertGateway(t *testing.T, authzStatus int, allowed bool, auditStatus int, auditBody string) (http.Handler, *[]alertAuthzCall, *int, *string) {
	t.Helper()
	calls := &[]alertAuthzCall{}
	var auditCalls int
	var auditTarget string
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst", "sre"})
	t.Cleanup(auth.Close)
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/authz/v1/check-access" {
			http.NotFound(w, r)
			return
		}
		var call alertAuthzCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		*calls = append(*calls, call)
		if authzStatus != http.StatusOK {
			http.Error(w, "internal detail must not leak", authzStatus)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed, "requires_approval": false, "decision_reason": "test"})
	}))
	t.Cleanup(authz.Close)
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls++
		auditTarget = r.URL.RequestURI()
		if auditStatus != http.StatusOK {
			http.Error(w, "internal audit detail", auditStatus)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, auditBody)
	}))
	t.Cleanup(audit.Close)
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).Routes()
	return gw, calls, &auditCalls, &auditTarget
}

func alertRequest(gw http.Handler, method, path string, withToken bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if withToken {
		req.Header.Set("Authorization", "Bearer tok-alice")
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func TestSessionAlerts_ListChecksDedicatedPermissionAndForwardsOnlyAllowedQuery(t *testing.T) {
	gw, calls, auditCalls, target := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"alerts":[],"has_more":false}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts?status=unacknowledged&severity=high&limit=25&since=2026-11-01T00%3A00%3A00Z", true)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("X-Content-Type-Options") != "nosniff" {
		t.Fatalf("list: %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(*calls) != 1 || (*calls)[0].Resource != "session-alerts:all" || (*calls)[0].Action != "session-alerts:read" || strings.Join((*calls)[0].Roles, ",") != "soc-analyst,sre" {
		t.Fatalf("authorization calls: %+v", *calls)
	}
	q, err := url.ParseQuery(strings.TrimPrefix(*target, "/audit/v1/session-alerts?"))
	if err != nil || q.Get("status") != "unacknowledged" || q.Get("severity") != "high" || q.Get("limit") != "25" || q.Get("since") != "2026-11-01T00:00:00Z" || len(q) != 4 {
		t.Fatalf("audit target %q: %v %v", *target, q, err)
	}
	if *auditCalls != 1 {
		t.Fatalf("Audit Service called %d times", *auditCalls)
	}
}

func TestSessionAlerts_SummaryUsesCollectionPermission(t *testing.T) {
	gw, calls, auditCalls, target := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"unacknowledged_count":0,"by_severity":{"info":0,"low":0,"medium":0,"high":0,"critical":0},"as_of":"2026-11-24T10:00:00Z","durable":true}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts/summary", true)
	if rec.Code != http.StatusOK || *target != "/audit/v1/session-alerts/summary" {
		t.Fatalf("summary: %d %q %s", rec.Code, *target, rec.Body.String())
	}
	if len(*calls) != 1 || (*calls)[0].Resource != "session-alerts:all" || (*calls)[0].Action != "session-alerts:read" || *auditCalls != 1 {
		t.Fatalf("calls=%+v audit=%d", *calls, *auditCalls)
	}
}

func TestSessionAlerts_DetailChecksExactOccurrencePermission(t *testing.T) {
	gw, calls, auditCalls, target := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"id":"alert_0123456789abcdef0123456789abcdef","rule_id":"session.breakglass","rule_version":"v1","source_event_id":"evt_0123456789abcdef","session_id":"session_1","severity":"high","status":"unacknowledged","summary":"Break-glass requested","detected_at":"2026-11-24T10:00:00Z","created_at":"2026-11-24T10:00:00Z","revision":1}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts/alert_0123456789abcdef0123456789abcdef", true)
	if rec.Code != http.StatusOK || *target != "/audit/v1/session-alerts/alert_0123456789abcdef0123456789abcdef" {
		t.Fatalf("detail: %d %q %s", rec.Code, *target, rec.Body.String())
	}
	if len(*calls) != 1 || (*calls)[0].Resource != "session-alerts:alert_0123456789abcdef0123456789abcdef" || (*calls)[0].Action != "session-alerts:read" || *auditCalls != 1 {
		t.Fatalf("calls=%+v audit=%d", *calls, *auditCalls)
	}
}

func TestSessionAlerts_DeniedPermissionNeverReachesAudit(t *testing.T) {
	gw, calls, auditCalls, _ := alertGateway(t, http.StatusOK, false, http.StatusOK, `{"alerts":[]}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts", true)
	if rec.Code != http.StatusForbidden || *auditCalls != 0 || len(*calls) != 1 {
		t.Fatalf("status=%d authz=%+v audit=%d", rec.Code, *calls, *auditCalls)
	}
}

func TestSessionAlerts_AuthorizationFailureFailsClosed(t *testing.T) {
	gw, calls, auditCalls, _ := alertGateway(t, http.StatusServiceUnavailable, true, http.StatusOK, `{"alerts":[]}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts", true)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "internal detail") || *auditCalls != 0 || len(*calls) != 1 {
		t.Fatalf("status=%d body=%q authz=%+v audit=%d", rec.Code, rec.Body.String(), *calls, *auditCalls)
	}
}

func TestSessionAlerts_NoTokenAndInvalidRoutesNeverReachUpstreams(t *testing.T) {
	for _, tc := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/session-alerts", http.StatusUnauthorized},
		{http.MethodGet, "/session-alerts/alert_0123456789abcdef0123456789abcdef/acknowledge", http.StatusMethodNotAllowed},
		{http.MethodGet, "/session-alerts/alert.123", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts/alert_0123456789ABCDEF0123456789abcdef", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts?cursor=not-a-cursor", http.StatusBadRequest},
		{http.MethodPost, "/session-alerts", http.StatusMethodNotAllowed},
		{http.MethodGet, "/session-alerts/summary?unexpected=1", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts?actorRoles=platform-admin", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts?limit=101", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts?severity=super-high", http.StatusBadRequest},
		{http.MethodGet, "/session-alerts?status=closed", http.StatusBadRequest},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			gw, calls, auditCalls, _ := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"alerts":[]}`)
			rec := alertRequest(gw, tc.method, tc.path, tc.want != http.StatusUnauthorized)
			if rec.Code != tc.want || len(*calls) != 0 || *auditCalls != 0 {
				t.Fatalf("status=%d want=%d authz=%+v audit=%d body=%s", rec.Code, tc.want, *calls, *auditCalls, rec.Body.String())
			}
		})
	}
}

func TestSessionAlerts_AuditFailureIsSanitized(t *testing.T) {
	gw, _, auditCalls, _ := alertGateway(t, http.StatusOK, true, http.StatusInternalServerError, "private database address")
	rec := alertRequest(gw, http.MethodGet, "/session-alerts", true)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "private database address") || *auditCalls != 1 {
		t.Fatalf("status=%d body=%q audit=%d", rec.Code, rec.Body.String(), *auditCalls)
	}
}

func TestSessionAlerts_RejectsUnexpectedUpstreamFields(t *testing.T) {
	gw, _, auditCalls, _ := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"alerts":[],"has_more":false,"credential":"must-not-leak"}`)
	rec := alertRequest(gw, http.MethodGet, "/session-alerts", true)
	if rec.Code != http.StatusBadGateway || strings.Contains(rec.Body.String(), "must-not-leak") || *auditCalls != 1 {
		t.Fatalf("status=%d body=%q audit=%d", rec.Code, rec.Body.String(), *auditCalls)
	}
}

func TestSessionAlerts_RefusesInternalRedirectsWithoutFollowingThem(t *testing.T) {
	var redirectedCalls int
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		redirectedCalls++
		_, _ = io.WriteString(w, `{"allowed":true}`)
	}))
	defer canary.Close()
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", canary.URL)
		w.WriteHeader(http.StatusFound)
	}))
	defer authz.Close()
	var auditCalls int
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		auditCalls++
		_, _ = io.WriteString(w, `{"alerts":[],"has_more":false}`)
	}))
	defer audit.Close()
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).Routes()
	rec := alertRequest(gw, http.MethodGet, "/session-alerts", true)
	if rec.Code != http.StatusServiceUnavailable || redirectedCalls != 0 || auditCalls != 0 {
		t.Fatalf("status=%d redirect target calls=%d audit calls=%d body=%s", rec.Code, redirectedCalls, auditCalls, rec.Body.String())
	}
}

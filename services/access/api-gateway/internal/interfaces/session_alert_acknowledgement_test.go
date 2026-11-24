package interfaces_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
)

func TestSessionAlertAcknowledgement_UsesExactPermissionAndVerifiedActor(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	calls := &[]alertAuthzCall{}
	var auditCalls int
	var auditPath, auditBody string
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var call alertAuthzCall
		if err := json.NewDecoder(r.Body).Decode(&call); err != nil {
			http.Error(w, "bad", 400)
			return
		}
		*calls = append(*calls, call)
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "requires_approval": false, "decision_reason": "test"})
	}))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls++
		auditPath = r.URL.RequestURI()
		data, _ := io.ReadAll(r.Body)
		auditBody = string(data)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"id":"`+alertID+`","status":"acknowledged","revision":2,"acknowledged_at":"2026-11-24T11:00:00Z","acknowledged_by":"u-alice","acknowledgement_event_id":"evt_ack_1"}`)
	}))
	defer audit.Close()
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).Routes()
	req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(*calls) != 1 || (*calls)[0].Resource != "session-alerts:"+alertID || (*calls)[0].Action != "session-alerts:acknowledge" || strings.Join((*calls)[0].Roles, ",") != "soc-analyst" {
		t.Fatalf("authorization calls = %+v", *calls)
	}
	if auditCalls != 1 || auditPath != "/audit/v1/session-alerts/"+alertID+"/acknowledge" {
		t.Fatalf("audit calls=%d path=%q", auditCalls, auditPath)
	}
	var forwarded struct {
		ActorID          string `json:"actor_id"`
		ExpectedRevision int64  `json:"expected_revision"`
	}
	if err := json.Unmarshal([]byte(auditBody), &forwarded); err != nil || forwarded.ActorID != "u-alice" || forwarded.ExpectedRevision != 1 {
		t.Fatalf("forwarded body = %q (%+v), err=%v", auditBody, forwarded, err)
	}
	if strings.Contains(auditBody, "attacker") {
		t.Fatalf("client actor leaked into internal request: %q", auditBody)
	}
}

func TestSessionAlertAcknowledgement_DenialAndAuthorizationFailureFailClosed(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	for _, tc := range []struct {
		name                           string
		authzStatus, auditStatus, want int
	}{
		{"denied", http.StatusOK, http.StatusOK, http.StatusForbidden},
		{"authorization unavailable", http.StatusServiceUnavailable, http.StatusOK, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			gw, calls, auditCalls, _ := alertGateway(t, tc.authzStatus, false, tc.auditStatus, `{"id":"`+alertID+`","status":"acknowledged","revision":2,"acknowledged_at":"2026-11-24T11:00:00Z","acknowledged_by":"u-alice","acknowledgement_event_id":"evt_ack_1"}`)
			req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
			req.Header.Set("Authorization", "Bearer tok-alice")
			rec := httptest.NewRecorder()
			gw.ServeHTTP(rec, req)
			if rec.Code != tc.want || len(*calls) != 1 || *auditCalls != 0 {
				t.Fatalf("status=%d want=%d authz=%+v audit=%d body=%s", rec.Code, tc.want, *calls, *auditCalls, rec.Body.String())
			}
		})
	}
}

func TestSessionAlertAcknowledgement_RejectsForgedBodyAndMapsConflicts(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	for _, body := range []string{`{"expected_revision":0}`, `{"expected_revision":1,"actorId":"attacker"}`, `{"expected_revision":1} {}`, `not-json`} {
		gw, calls, auditCalls, _ := alertGateway(t, http.StatusOK, true, http.StatusOK, `{}`)
		req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || len(*calls) != 0 || *auditCalls != 0 {
			t.Errorf("body %q: status=%d authz=%d audit=%d", body, rec.Code, len(*calls), *auditCalls)
		}
	}
	for _, tc := range []struct{ status, want int }{{http.StatusConflict, http.StatusConflict}, {http.StatusNotFound, http.StatusNotFound}, {http.StatusServiceUnavailable, http.StatusServiceUnavailable}} {
		gw, _, auditCalls, _ := alertGateway(t, http.StatusOK, true, tc.status, "internal detail")
		req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code != tc.want || *auditCalls != 1 || strings.Contains(rec.Body.String(), "internal detail") {
			t.Errorf("upstream=%d status=%d want=%d body=%q", tc.status, rec.Code, tc.want, rec.Body.String())
		}
	}
}

func TestSessionAlertAcknowledgement_ConsumesSharedWriteActionBudget(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	var auditCalls int
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, `{"allowed":true}`) }))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		auditCalls++
		_, _ = io.WriteString(w, `{"id":"`+alertID+`","status":"acknowledged","revision":2,"acknowledged_at":"2026-11-24T11:00:00Z","acknowledged_by":"u-alice","acknowledgement_event_id":"evt_ack_1"}`)
	}))
	defer audit.Close()
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).WithSessionActionLimiter(application.NewRateLimiter(1, time.Hour)).Routes()
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}
	if first := request(); first.Code != http.StatusOK {
		t.Fatalf("first acknowledgement status %d: %s", first.Code, first.Body.String())
	}
	if second := request(); second.Code != http.StatusTooManyRequests {
		t.Fatalf("second acknowledgement status %d, want 429", second.Code)
	}
	if auditCalls != 1 {
		t.Fatalf("Audit Service called %d times, want 1", auditCalls)
	}
}

func TestSessionAlertAcknowledgement_PolicyRevocationStopsSubsequentWrite(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	allowed := true
	var auditCalls int
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed, "requires_approval": false, "decision_reason": "test"})
	}))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		auditCalls++
		_, _ = io.WriteString(w, `{"id":"`+alertID+`","status":"acknowledged","revision":2,"acknowledged_at":"2026-11-24T11:00:00Z","acknowledged_by":"u-alice","acknowledgement_event_id":"evt_ack_1"}`)
	}))
	defer audit.Close()
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).Routes()
	request := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}
	if first := request(); first.Code != http.StatusOK {
		t.Fatalf("authorized acknowledgement: %d %s", first.Code, first.Body.String())
	}
	allowed = false // simulate immediate policy revocation at the Authorization boundary
	if second := request(); second.Code != http.StatusForbidden {
		t.Fatalf("after policy revocation: %d %s, want 403", second.Code, second.Body.String())
	}
	if auditCalls != 1 {
		t.Fatalf("Audit Service called %d times, want no call after revocation", auditCalls)
	}
}

func TestSessionAlertAcknowledgement_ApprovalRequiredDoesNotExecute(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	var auditCalls int
	auth := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"soc-analyst"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": true, "requires_approval": true, "decision_reason": "approval required"})
	}))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { auditCalls++; _, _ = io.WriteString(w, `{}`) }))
	defer audit.Close()
	gw := newTestGateway(t, auth.URL, "", "", authz.URL).WithAuditServiceURL(audit.URL).Routes()
	req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || auditCalls != 0 {
		t.Fatalf("status=%d audit=%d body=%s", rec.Code, auditCalls, rec.Body.String())
	}
}

func TestSessionAlertAcknowledgement_IdempotentRetryReturnsOriginalActor(t *testing.T) {
	const alertID = "alert_0123456789abcdef0123456789abcdef"
	gw, _, auditCalls, _ := alertGateway(t, http.StatusOK, true, http.StatusOK, `{"id":"`+alertID+`","status":"acknowledged","revision":2,"acknowledged_at":"2026-11-24T11:00:00Z","acknowledged_by":"u-original-operator","acknowledgement_event_id":"evt_ack_1"}`)
	req := httptest.NewRequest(http.MethodPost, "/session-alerts/"+alertID+"/acknowledge", strings.NewReader(`{"expected_revision":1}`))
	req.Header.Set("Authorization", "Bearer tok-alice")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"acknowledged_by":"u-original-operator"`) || *auditCalls != 1 {
		t.Fatalf("idempotent retry: status=%d calls=%d body=%s", rec.Code, *auditCalls, rec.Body.String())
	}
}

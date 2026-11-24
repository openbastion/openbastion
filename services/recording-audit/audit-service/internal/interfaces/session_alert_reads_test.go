package interfaces_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func TestHTTP_SessionAlertReadRoutesAreBoundedAndNoStore(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAsWithDetails(context.Background(), "session-broker", "operator-1", "session.breakglass_requested", "session", "session-1", map[string]string{"credential": "must-not-be-copied"}, true); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ProcessSessionAlertDetections(context.Background(), 10); err != nil {
		t.Fatal(err)
	}
	h := interfaces.NewHTTPServer(svc).Routes()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/v1/session-alerts?status=unacknowledged&severity=high&limit=1", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `"has_more":false`) {
		t.Fatalf("list: %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	var page struct {
		Alerts []struct {
			ID string `json:"id"`
		} `json:"alerts"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &page); err != nil || len(page.Alerts) != 1 || page.Alerts[0].ID == "" {
		t.Fatalf("decode list response: %v %s", err, rec.Body.String())
	}
	for _, forbidden := range []string{"must-not-be-copied", `"credential"`, `"details"`, "clipboard"} {
		if strings.Contains(rec.Body.String(), forbidden) {
			t.Fatalf("sensitive source field %q leaked: %s", forbidden, rec.Body.String())
		}
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/v1/session-alerts/summary", nil))
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" || !strings.Contains(rec.Body.String(), `"durable":false`) || !strings.Contains(rec.Body.String(), `"unacknowledged_count":1`) {
		t.Fatalf("summary: %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/v1/session-alerts/"+page.Alerts[0].ID, nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"source_event_id"`) {
		t.Fatalf("detail: %d %s", rec.Code, rec.Body.String())
	}

	for _, path := range []string{"/audit/v1/session-alerts?limit=101", "/audit/v1/session-alerts?status=unknown", "/audit/v1/session-alerts?cursor=bad", "/audit/v1/session-alerts?unexpected=x", "/audit/v1/session-alerts?limit=1&limit=2", "/audit/v1/session-alerts?severity=", "/audit/v1/session-alerts?since=%ZZ"} {
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %q, want 400", path, rec.Code, rec.Body.String())
		}
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/audit/v1/session-alerts/not-an-id", nil))
	if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("invalid id: %d headers=%v body=%q", rec.Code, rec.Header(), rec.Body.String())
	}
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/audit/v1/session-alerts", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST list: %d", rec.Code)
	}
}

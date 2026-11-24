package interfaces_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func TestHTTP_SessionAlertAcknowledgementIsStrictAndIdempotent(t *testing.T) {
	ctx := context.Background()
	store := infrastructure.NewInMemoryStore()
	svc := application.NewAuditService(store)
	if _, err := svc.EmitEventAs(ctx, "session-broker", "requester-1", "session.breakglass_requested", "session", "session-ack-http", false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.ProcessSessionAlertDetections(ctx, 10); err != nil {
		t.Fatal(err)
	}
	alert := store.SessionAlerts()[0]
	h := interfaces.NewHTTPServer(svc).Routes()
	path := "/audit/v1/session-alerts/" + alert.ID + "/acknowledge"
	request := func(body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		return rec
	}
	rec := request(`{"actor_id":"auditor-1","expected_revision":1}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"acknowledged"`) || !strings.Contains(rec.Body.String(), `"acknowledgement_event_id"`) || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("acknowledge: %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	countAfterFirst, _ := store.All(ctx)
	rec = request(`{"actor_id":"auditor-1","expected_revision":1}`)
	countAfterRetry, _ := store.All(ctx)
	if rec.Code != http.StatusOK || len(countAfterRetry) != len(countAfterFirst) {
		t.Fatalf("retry: %d events %d -> %d body=%s", rec.Code, len(countAfterFirst), len(countAfterRetry), rec.Body.String())
	}
	for _, body := range []string{
		`{"actor_id":"auditor-1","expected_revision":0}`,
		`{"actor_id":"auditor-1","expected_revision":1,"extra":"x"}`,
		`{"actor_id":"auditor-1","expected_revision":1} {}`,
	} {
		rec = request(body)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("body %q: status %d, want 400", body, rec.Code)
		}
	}
	stale := httptest.NewRecorder()
	h.ServeHTTP(stale, httptest.NewRequest(http.MethodPost, "/audit/v1/session-alerts/alert_00000000000000000000000000000000/acknowledge", strings.NewReader(`{"actor_id":"auditor-1","expected_revision":1}`)))
	if stale.Code != http.StatusNotFound {
		t.Fatalf("unknown alert status %d, want 404", stale.Code)
	}
}

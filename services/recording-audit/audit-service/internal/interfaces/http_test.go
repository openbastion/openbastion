package interfaces_test

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/interfaces"
)

func post(h http.Handler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/audit/v1/emit-event", strings.NewReader(body)))
	return rec
}

// ADR-0025: what the HTTP layer answers for each way an event is not taken.
func TestHTTP_EmitEventAnswersForWhatItRefuses(t *testing.T) {
	h := interfaces.NewHTTPServer(application.NewAuditService(infrastructure.NewInMemoryStore())).Routes()

	if rec := post(h, `{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s1","success":true}`); rec.Code != http.StatusOK {
		t.Fatalf("a valid event: %d %s", rec.Code, rec.Body)
	}
	rec := post(h, `{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"SECRETVALUE`+strings.Repeat("x", 300)+`","success":true}`)
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "resource_id") || strings.Contains(rec.Body.String(), "SECRETVALUE") {
		t.Fatalf("an invalid field: %d %q, want 400 naming the field and not the value", rec.Code, rec.Body)
	}
	for _, body := range []string{`{"actor_id": SECRETVALUE}`, `{"success":"SECRETVALUE"}`, `{"actor_id":42}`} {
		rec = post(h, body)
		if rec.Code != http.StatusBadRequest || strings.Contains(rec.Body.String(), "SECRETVALUE") ||
			strings.Contains(rec.Body.String(), "Go struct") || strings.Contains(rec.Body.String(), "emitEventRequest") {
			t.Fatalf("%s: %d %q, want a 400 that quotes neither the body nor the code", body, rec.Code, rec.Body)
		}
	}
	big := `{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s1","pad":"` + strings.Repeat("p", 17<<10) + `"}`
	if rec := post(h, big); rec.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("a 17 KiB body: %d, want 413", rec.Code)
	}
	near := `{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s1","pad":"` + strings.Repeat("p", 15<<10) + `"}`
	if rec := post(h, near); rec.Code != http.StatusOK {
		t.Fatalf("a 15 KiB body: %d %s, want 200 (the bound is 16 KiB)", rec.Code, rec.Body)
	}
	for _, m := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(m, "/audit/v1/emit-event", nil))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d, want 405", m, rec.Code)
		}
	}
}

type failingStore struct{ *infrastructure.InMemoryStore }

func (failingStore) Append(context.Context, *domain.Event) error {
	return errors.New("pq: relation audit_events at 10.0.0.5:5432 is gone")
}

func TestHTTP_AStoreFailureIsGenericToTheEmitter_AndInTheLog(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)
	h := interfaces.NewHTTPServer(application.NewAuditService(failingStore{infrastructure.NewInMemoryStore()})).Routes()
	rec := post(h, `{"actor_id":"u_1","action":"session.read","resource_type":"session","resource_id":"s1","success":true}`)
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("%d %q, want a generic 500", rec.Code, rec.Body)
	}
	if !strings.Contains(logs.String(), "10.0.0.5") {
		t.Fatalf("the cause is not in the log: %q", logs.String())
	}
}

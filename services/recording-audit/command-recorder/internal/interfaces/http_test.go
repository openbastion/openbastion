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
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/interfaces"
)

type allowAll struct{}

func (allowAll) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return true, "", nil
}

type notReadyStore struct {
	*infrastructure.InMemoryStore
	err error
}

func (s notReadyStore) Ready(context.Context) error { return s.err }

func get(t *testing.T, h http.Handler, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// Liveness and readiness differ on purpose: a recorder whose database is gone
// is alive (restarting it would not help) but must not be sent sessions.
func TestHTTP_ReadyzReflectsTheStoreWhileHealthzOnlyReflectsTheProcess(t *testing.T) {
	ready := interfaces.NewHTTPServer(application.NewRecorderService(infrastructure.NewInMemoryStore(), allowAll{}, nil)).Routes()
	if rec := get(t, ready, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("a ready recorder answered %d", rec.Code)
	}

	secret := errors.New(`pq: dial tcp 10.20.30.40:5432: connect: connection refused (database "openbastion", user "recorder")`)
	down := interfaces.NewHTTPServer(application.NewRecorderService(notReadyStore{InMemoryStore: infrastructure.NewInMemoryStore(), err: secret}, allowAll{}, nil)).Routes()

	rec := get(t, down, "/readyz")
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a recorder whose store is down answered %d, want 503", rec.Code)
	}
	// The endpoint is reachable by every proxy: the reason stays in the log.
	for _, leak := range []string{"10.20.30.40", "openbastion", "recorder", "pq:"} {
		if strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("the readiness response leaks %q: %q", leak, rec.Body.String())
		}
	}
	if rec := get(t, down, "/healthz"); rec.Code != http.StatusOK {
		t.Fatalf("liveness must not depend on the store, got %d", rec.Code)
	}
}

// -- GET /recorder/v1/sessions/{id}/commands (ADR-0022) ------------------------

type spyAudit struct {
	err    error
	actors []string
}

func (s *spyAudit) EmitEvent(_ context.Context, actorID, _, _, _ string, _ bool) error {
	if s.err != nil {
		return s.err
	}
	s.actors = append(s.actors, actorID)
	return nil
}

type failingStore struct{ *infrastructure.InMemoryStore }

func (failingStore) ListBySession(context.Context, string, int, int) ([]domain.CommandEntry, int, error) {
	return nil, 0, errors.New("pq: relation session_command_entries at 10.0.0.7:5432 is gone")
}

func recordOne(t *testing.T, store *infrastructure.InMemoryStore) {
	t.Helper()
	if err := store.AppendBatch(context.Background(), []domain.CommandEntry{{SessionID: "s1", Timestamp: time.Now(), Command: "cat /etc/shadow"}}); err != nil {
		t.Fatal(err)
	}
}

func TestHTTP_TheReadIsOnTheRecordUnderTheCallerTheGatewayNamed(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	recordOne(t, store)
	audit := &spyAudit{}
	h := interfaces.NewHTTPServer(application.NewRecorderService(store, allowAll{}, audit)).Routes()

	rec := get(t, h, "/recorder/v1/sessions/s1/commands?callerId=u_carol&actorRoles=auditor")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "cat /etc/shadow") {
		t.Fatalf("served read: %d %s", rec.Code, rec.Body)
	}
	if len(audit.actors) != 1 || audit.actors[0] != "u_carol" {
		t.Fatalf("the read is on the record under %q, want the Gateway's u_carol", audit.actors)
	}
	if rec := get(t, h, "/recorder/v1/sessions/s1/commands?actorRoles=auditor"); rec.Code != http.StatusForbidden {
		t.Fatalf("no callerId: %d, want 403", rec.Code)
	}
}

// What the Gateway relays to the client says nothing of the recording or of the failure;
// the cause is in the recorder's log.
func TestHTTP_AReadThatCouldNotBeRecordedOrReadIsGenericToTheClient(t *testing.T) {
	var logs bytes.Buffer
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	store := infrastructure.NewInMemoryStore()
	recordOne(t, store)
	down := &spyAudit{err: errors.New("dial tcp 10.0.0.9:8082: connection refused")}
	cases := []struct {
		name   string
		svc    *application.RecorderService
		status int
		cause  string
	}{
		{"audit down", application.NewRecorderService(store, allowAll{}, down), http.StatusServiceUnavailable, "10.0.0.9:8082"},
		{"store down", application.NewRecorderService(failingStore{store}, allowAll{}, &spyAudit{}), http.StatusInternalServerError, "10.0.0.7:5432"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			logs.Reset()
			rec := get(t, interfaces.NewHTTPServer(c.svc).Routes(), "/recorder/v1/sessions/s1/commands?callerId=u_carol&actorRoles=auditor")
			if rec.Code != c.status {
				t.Fatalf("%d %s, want %d", rec.Code, rec.Body, c.status)
			}
			for _, leak := range []string{"cat /etc/shadow", "s1", c.cause, "u_carol"} {
				if strings.Contains(rec.Body.String(), leak) {
					t.Fatalf("the body tells %q: %q", leak, rec.Body)
				}
			}
			if !strings.Contains(logs.String(), c.cause) || !strings.Contains(logs.String(), "s1") {
				t.Fatalf("the cause is not in the log: %q", logs.String())
			}
		})
	}
}

// What cannot be a session is a 400 for everyone, before anything is asked (ADR-0024).
func TestHTTP_AnIDThatCannotBeASessionIsA400(t *testing.T) {
	audit := &spyAudit{}
	h := interfaces.NewHTTPServer(application.NewRecorderService(infrastructure.NewInMemoryStore(), allowAll{}, audit)).Routes()
	for _, id := range []string{strings.Repeat("x", 257), "s%FF1"} {
		rec := get(t, h, "/recorder/v1/sessions/"+id+"/commands?callerId=u_carol&actorRoles=auditor")
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "not a session id") {
			t.Fatalf("%q: %d %q, want 400", id, rec.Code, rec.Body)
		}
	}
	if len(audit.actors) != 0 {
		t.Fatalf("events for ids that cannot be sessions: %q", audit.actors)
	}
}

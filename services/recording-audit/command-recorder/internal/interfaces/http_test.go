package interfaces_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/application"
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
	ready := interfaces.NewHTTPServer(application.NewRecorderService(infrastructure.NewInMemoryStore(), allowAll{})).Routes()
	if rec := get(t, ready, "/readyz"); rec.Code != http.StatusOK {
		t.Fatalf("a ready recorder answered %d", rec.Code)
	}

	secret := errors.New(`pq: dial tcp 10.20.30.40:5432: connect: connection refused (database "openbastion", user "recorder")`)
	down := interfaces.NewHTTPServer(application.NewRecorderService(notReadyStore{InMemoryStore: infrastructure.NewInMemoryStore(), err: secret}, allowAll{})).Routes()

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

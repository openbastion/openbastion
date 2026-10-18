package interfaces_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/interfaces"
)

type allowAuthz struct{}

func (allowAuthz) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return true, "", nil
}

type okVault struct{}

func (okVault) AuthorizeScope(context.Context, string, string, string, time.Duration) (string, time.Time, error) {
	return "scope", time.Now().Add(time.Minute), nil
}

type quietAudit struct{}

func (quietAudit) EmitEvent(context.Context, string, string, string, string, bool) error { return nil }

type oneAccount struct{}

func (oneAccount) GetAccount(context.Context, string) (string, string, error) {
	return "10.0.0.5:22", "root", nil
}

type failingProxy struct{ err error }

func (p failingProxy) EstablishSession(context.Context, string, string, string, string, time.Duration) (string, string, error) {
	return "", "", p.err
}

func connect(t *testing.T, proxyErr error) *httptest.ResponseRecorder {
	t.Helper()
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{err: proxyErr})
	sess, err := svc.CreateSession(context.Background(), "alice", []string{"dba"}, "acc1", "ssh", "incident", 60)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(svc).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/connect", nil))
	return rec
}

// "I cannot connect because nothing could record me" is a 503 the operator can
// act on (try again shortly) — not the 409 that means the session itself is in
// the wrong state.
func TestConnect_ARecordingRefusalIsA503NotA409(t *testing.T) {
	rec := connect(t, fmt.Errorf("%w: establish-session refused by the proxy", domain.ErrRecordingUnavailable))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "recording unavailable") {
		t.Fatalf("the operator is not told why: %q", rec.Body.String())
	}
}

func TestConnect_OtherProxyFailuresStayAConflict(t *testing.T) {
	if rec := connect(t, fmt.Errorf("establish-session: status 500")); rec.Code != http.StatusConflict {
		t.Fatalf("got %d, want 409", rec.Code)
	}
}

package interfaces_test

import (
	"context"
	"encoding/json"
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

func (p failingProxy) EstablishSession(context.Context, string, string, string, string, time.Duration, bool) (string, string, error) {
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
	interfaces.NewHTTPServer(svc).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/connect", strings.NewReader(`{"callerId":"alice"}`)))
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

// -- break-glass over HTTP (ADR-0009) --------------------------------------------

func postSession(t *testing.T, svc *application.SessionBrokerService, body string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(svc).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(body)))
	return rec
}

func newBreakGlassService(maxMinutes int) *application.SessionBrokerService {
	return application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(maxMinutes).WithoutBreakGlassApproval() // ADR-0009 tests: approval has its own
}

const bgBody = `{"requestedBy":"oncall","actorRoles":["sre"],"targetAccountId":"acc1","protocol":"ssh","justification":"recorder down, P1 incident","durationMinutes":15%s}`

func TestPostSessions_BreakGlassIsAskedForByName(t *testing.T) {
	svc := newBreakGlassService(30)

	rec := postSession(t, svc, fmt.Sprintf(bgBody, `,"breakGlass":true`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	var got struct {
		BreakGlass bool `json:"breakGlass"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || !got.BreakGlass {
		t.Fatalf("the response does not say the session is break-glass: %v %q", err, rec.Body.String())
	}

	// The same request without the member is an ordinary session, whatever the
	// platform allows: break-glass is requested, never assumed.
	rec = postSession(t, svc, fmt.Sprintf(bgBody, ``))
	if rec.Code != http.StatusCreated {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
	got.BreakGlass = true
	_ = json.Unmarshal(rec.Body.Bytes(), &got)
	if got.BreakGlass {
		t.Fatalf("an ordinary session came back marked break-glass: %q", rec.Body.String())
	}
}

func TestPostSessions_ARefusedBreakGlassRequestIsAForbidden(t *testing.T) {
	rec := postSession(t, newBreakGlassService(0), fmt.Sprintf(bgBody, `,"breakGlass":true`)) // not enabled
	if rec.Code != http.StatusForbidden {
		t.Fatalf("got %d, want 403: %q", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), "break-glass") {
		t.Fatalf("the refusal does not say what was refused: %q", rec.Body.String())
	}
}

package interfaces_test

import (
	"context"
	"encoding/json"
	"errors"
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

func (oneAccount) CheckAccount(context.Context, string) error { return nil }

func (oneAccount) GetAccount(context.Context, string) (string, string, error) {
	return "10.0.0.5:22", "root", nil
}

type failingProxy struct{ err error }

func (p failingProxy) EstablishSession(context.Context, string, string, string, string, time.Duration, bool) (string, string, error) {
	return "", "", p.err
}

// RevokeSession succeeds: the proxy of these tests has nothing open.
func (p failingProxy) RevokeSession(context.Context, string, time.Duration) error { return nil }

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

// A dependency that fails is not a state of the session (ADR-0042): 503, and its own text —
// which can name an address — never reaches the client. (This was a 409 with the cause until
// ADR-0042; docs/api/rest/openapi.yaml keeps 409 for a session that cannot be connected in its state.)
func TestConnect_AFailingDependencyIsA503_WithoutItsCause(t *testing.T) {
	rec := connect(t, fmt.Errorf("establish-session: Post \"https://10.9.8.7:8085/internal\": dial tcp 10.9.8.7:8085: connection refused"))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "10.9.8.7") || strings.Contains(rec.Body.String(), "dial tcp") {
		t.Fatalf("the cause reached the client: %q", rec.Body.String())
	}
}

// pinlessVault refuses every scope as the Vault does for an account with no pinned host key.
type pinlessVault struct{}

func (pinlessVault) AuthorizeScope(context.Context, string, string, string, time.Duration) (string, time.Time, error) {
	return "", time.Time{}, fmt.Errorf("authorize-scope: %w", domain.ErrAccountNotPinned)
}

// The Vault's reason reaches the operator as what to do (ADR-0042, ADR-0039).
func TestConnect_AnUnpinnedAccountIsA409_ThatSaysWhatToDo(t *testing.T) {
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, pinlessVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	sess, err := svc.CreateSession(context.Background(), "alice", []string{"dba"}, "acc1", "ssh", "incident", 60)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(svc).Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/connect", strings.NewReader(`{"callerId":"alice"}`)))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "no pinned host key") || !strings.Contains(rec.Body.String(), "host-key") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

func TestConnect_UnknownSessionIs404_AndAStateIs409(t *testing.T) {
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	srv := interfaces.NewHTTPServer(svc).Routes()
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/session_nope/connect", strings.NewReader(`{"callerId":"alice"}`)))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("unknown session: %d", rec.Code)
	}
	sess, _ := svc.CreateSession(context.Background(), "alice", []string{"dba"}, "acc1", "ssh", "incident", 60)
	if _, err := svc.TerminateSession(context.Background(), sess.ID, "alice", []string{"dba"}); err != nil {
		t.Fatal(err)
	}
	rec = httptest.NewRecorder()
	srv.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/connect", strings.NewReader(`{"callerId":"alice"}`)))
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "cannot connect a session in status") {
		t.Fatalf("a terminated session: %d %q", rec.Code, rec.Body.String())
	}
}

// failingAudit cannot write.
type failingAudit struct{}

func (failingAudit) EmitEvent(context.Context, string, string, string, string, bool) error {
	return fmt.Errorf("emit-event: dial tcp 10.9.8.5:8082: connection refused")
}

// POST /sessions with a dependency down is the 503 docs/api/rest/openapi.yaml promises, without the cause; a refusal
// stays a 403 (ADR-0042).
func TestCreateSession_ADependencyDownIsA503_WithoutItsCause(t *testing.T) {
	for name, svc := range map[string]*application.SessionBrokerService{
		"authorization down": application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), downAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}),
		"audit down":         application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, failingAudit{}, oneAccount{}, failingProxy{}),
	} {
		rec := postSession(t, svc, `{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"incident","durationMinutes":60}`)
		if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "10.9.8.") || strings.Contains(rec.Body.String(), leak) {
			t.Fatalf("%s: %d %q", name, rec.Code, rec.Body.String())
		}
	}
	// Counter-proof: a refusal is a 403 that says why.
	rec := postSession(t, application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), denyAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}),
		`{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"incident","durationMinutes":60}`)
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "access denied") {
		t.Fatalf("a refusal: %d %q", rec.Code, rec.Body.String())
	}
}

type denyAuthz struct{}

func (denyAuthz) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return false, "no policy grants it", nil
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

// checkedAccount answers CheckAccount with err.
type checkedAccount struct {
	oneAccount
	err error
}

func (c checkedAccount) CheckAccount(context.Context, string) error { return c.err }

// ADR-0043 over HTTP: POST /sessions says an unknown account (404) and an unpinned one (409);
// a Vault that cannot be asked is a 503 that names nothing of it.
func TestCreateSession_TheAccountIsCheckedFirst_OverHTTP(t *testing.T) {
	body := `{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"incident","durationMinutes":60}`
	for name, c := range map[string]struct {
		err    error
		status int
		says   string
	}{
		"unknown":    {domain.ErrAccountNotFound, http.StatusNotFound, "privileged account not found"},
		"unpinned":   {domain.ErrAccountNotPinned, http.StatusConflict, "no pinned host key"},
		"Vault down": {fmt.Errorf("Get \"http://10.9.8.4:8081/vault/v1/accounts/acc1\": %s", leak), http.StatusServiceUnavailable, "try again shortly"},
	} {
		svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, checkedAccount{err: c.err}, failingProxy{})
		rec := postSession(t, svc, body)
		if rec.Code != c.status || !strings.Contains(rec.Body.String(), c.says) || strings.Contains(rec.Body.String(), "10.9.8.") {
			t.Fatalf("%s: %d %q", name, rec.Code, rec.Body.String())
		}
	}
}

// ADR-0043: the Authorization Service unreachable while a break-glass is asked is a 503 that
// names nothing of it (it was a 403 with its address).
func TestCreateBreakGlass_AuthorizationDownIsA503_ThatNamesNothing(t *testing.T) {
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), breakGlassDownAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(60)
	rec := postSession(t, svc, `{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"the database is down, incident 42","durationMinutes":30,"breakGlass":true}`)
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "10.9.8.") || strings.Contains(rec.Body.String(), "dial tcp") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// breakGlassDownAuthz allows sessions, and cannot be reached for a break-glass decision.
type breakGlassDownAuthz struct{}

func (breakGlassDownAuthz) CheckAccess(_ context.Context, _ []string, resource, _ string) (bool, string, error) {
	if strings.HasPrefix(resource, "breakglass:") {
		return false, "", errors.New(leak)
	}
	return true, "", nil
}

package interfaces_test

// The double validation of break-glass over HTTP (ADR-0011): the routes, their status
// codes, and the two things a client must never learn or choose — a dependency's own error
// message, and who the caller is.

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/interfaces"
)

// leakyAudit fails like a real network would: with an address in the message.
type leakyAudit struct{ failing bool }

const leak = "dial tcp 10.9.8.7:8082: connect: connection refused"

func (a *leakyAudit) EmitEvent(context.Context, string, string, string, string, bool) error {
	if a.failing {
		return errors.New(leak)
	}
	return nil
}

type downAuthz struct{}

func (downAuthz) CheckAccess(context.Context, []string, string, string) (bool, string, error) {
	return false, "", errors.New(leak)
}

// approvalService is the Broker on its strict default: approval required, nobody told otherwise.
func approvalService(authz application.AuthorizationClient, audit application.AuditEmitter) *application.SessionBrokerService {
	return application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), authz, okVault{}, audit, oneAccount{}, failingProxy{}).WithBreakGlass(30)
}

func send(svc *application.SessionBrokerService, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	interfaces.NewHTTPServer(svc).Routes().ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

const askForBreakGlass = `{"requestedBy":"alice","actorRoles":["sre"],"targetAccountId":"acc1","protocol":"ssh","justification":"recorder down during P1 incident","durationMinutes":20,"breakGlass":true}`

func requestOverHTTP(t *testing.T, svc *application.SessionBrokerService) (id string) {
	t.Helper()
	rec := send(svc, http.MethodPost, "/sessions", askForBreakGlass)
	if rec.Code != http.StatusCreated {
		t.Fatalf("request: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "pending_approval" {
		t.Fatalf("a break-glass request should wait: %s", rec.Body.String())
	}
	if exp, _ := out["expiresAt"].(string); exp == "" {
		t.Fatalf("a pending request says nothing of its deadline: %s", rec.Body.String())
	}
	return out["id"].(string)
}

func decisionBody(by string) string {
	return `{"decidedBy":"` + by + `","actorRoles":["lead"]}`
}

func TestApprovalOverHTTP_TheWholeLifecycle(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{})
	id := requestOverHTTP(t, svc)

	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/connect", `{"callerId":"alice"}`); rec.Code != http.StatusConflict {
		t.Fatalf("connecting a pending request: %d, want 409", rec.Code)
	}

	rec := send(svc, http.MethodPost, "/sessions/"+id+"/approve", decisionBody("bob"))
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out["status"] != "active" || out["decidedBy"] != "bob" || out["decidedAt"] == "" || out["decidedAt"] == nil {
		t.Fatalf("approved = %s", rec.Body.String())
	}

	// GET shows the same, so the requester can see that it was approved, and by whom.
	if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"decidedBy":"bob"`) {
		t.Fatalf("GET: %s", rec.Body.String())
	}

	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/connect", `{"callerId":"bob"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("the approver connecting: %d, want 403", rec.Code)
	}
	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/connect", `{"callerId":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("the requester connecting after approval: %d %s", rec.Code, rec.Body.String())
	}
}

func TestApprovalOverHTTP_StatusCodes(t *testing.T) {
	svc := approvalService(allowAuthz{}, quietAudit{})
	id := requestOverHTTP(t, svc)

	for name, c := range map[string]struct {
		method, path, body string
		want               int
		contains           string
	}{
		"approving one's own request": {http.MethodPost, "/sessions/" + id + "/approve", decisionBody("alice"), http.StatusForbidden, "person who made it"},
		"an unknown session":          {http.MethodPost, "/sessions/nope/approve", decisionBody("bob"), http.StatusNotFound, ""},
		"no identity":                 {http.MethodPost, "/sessions/" + id + "/approve", `{}`, http.StatusForbidden, "authenticated user"},
		"not JSON":                    {http.MethodPost, "/sessions/" + id + "/approve", `not json`, http.StatusBadRequest, ""},
		"a body past the bound":       {http.MethodPost, "/sessions/" + id + "/approve", `{"decidedBy":"bob","actorRoles":["` + strings.Repeat("x", 1<<17) + `"]}`, http.StatusBadRequest, ""},
		"approve by GET":              {http.MethodGet, "/sessions/" + id + "/approve", "", http.StatusMethodNotAllowed, ""},
		"reject by DELETE":            {http.MethodDelete, "/sessions/" + id + "/reject", "", http.StatusMethodNotAllowed, ""},
	} {
		t.Run(name, func(t *testing.T) {
			rec := send(svc, c.method, c.path, c.body)
			if rec.Code != c.want || !strings.Contains(rec.Body.String(), c.contains) {
				t.Fatalf("%d %q, want %d containing %q", rec.Code, rec.Body.String(), c.want, c.contains)
			}
		})
	}

	// Nothing above decided anything.
	if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"status":"pending_approval"`) {
		t.Fatalf("a refused decision changed the request: %s", rec.Body.String())
	}

	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/reject", decisionBody("bob")); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"denied"`) {
		t.Fatalf("reject: %d %s", rec.Code, rec.Body.String())
	}
	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/approve", decisionBody("bob")); rec.Code != http.StatusConflict {
		t.Fatalf("approving a rejected request: %d, want 409", rec.Code)
	}
}

// A dependency that does not answer is a 503 — the decision was not taken, and the
// client can try again — and the reason it gives stays in the Broker's log: it can
// carry an address.
func TestApprovalOverHTTP_ADependencyFailureIsA503_WithoutItsMessage(t *testing.T) {
	previous := log.Writer()
	log.SetOutput(io.Discard)
	t.Cleanup(func() { log.SetOutput(previous) })

	t.Run("the audit cannot record the decision", func(t *testing.T) {
		audit := &leakyAudit{}
		svc := approvalService(allowAuthz{}, audit)
		id := requestOverHTTP(t, svc)
		audit.failing = true
		rec := send(svc, http.MethodPost, "/sessions/"+id+"/approve", decisionBody("bob"))
		assertUnavailableWithoutLeak(t, rec)
		audit.failing = false
		if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), "pending_approval") {
			t.Fatalf("the request is not waiting any more: %s", rec.Body.String())
		}
	})

	t.Run("the Authorization Service cannot be asked", func(t *testing.T) {
		store := infrastructure.NewInMemoryStore()
		good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
		id := requestOverHTTP(t, good)
		down := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{}).WithBreakGlass(30)
		assertUnavailableWithoutLeak(t, send(down, http.MethodPost, "/sessions/"+id+"/approve", decisionBody("bob")))
	})
}

func assertUnavailableWithoutLeak(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("%d %q, want 503", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "10.9.8.7") || strings.Contains(rec.Body.String(), "dial tcp") {
		t.Fatalf("a dependency's own error reached the client: %q", rec.Body.String())
	}
}

// Only the requester connects, and the Broker takes the caller's name from the body the
// Gateway builds — an absent or unreadable one names nobody.
func TestConnectOverHTTP_OnlyTheRequesterMayConnect(t *testing.T) {
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	rec := send(svc, http.MethodPost, "/sessions", `{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"routine","durationMinutes":20}`)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	id := out["id"].(string)

	for name, body := range map[string]string{
		"no body":              ``,
		"not JSON":             `callerId=alice`,
		"an empty caller":      `{"callerId":""}`,
		"another caller":       `{"callerId":"mallory"}`,
		"the field misspelled": `{"caller":"alice"}`,
	} {
		t.Run(name, func(t *testing.T) {
			if rec := send(svc, http.MethodPost, "/sessions/"+id+"/connect", body); rec.Code != http.StatusForbidden {
				t.Fatalf("%d %q, want 403", rec.Code, rec.Body.String())
			}
		})
	}
	if rec := send(svc, http.MethodPost, "/sessions/"+id+"/connect", `{"callerId":"alice"}`); rec.Code != http.StatusOK {
		t.Fatalf("the requester: %d %s", rec.Code, rec.Body.String())
	}
}

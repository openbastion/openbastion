package interfaces_test

// Ending a session over HTTP (ADR-0017): the Broker takes the caller from the body the
// Gateway builds, and only from there; the codes say which of the session, the caller and
// the state is the reason; and a dependency's own message stays in the log.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// terminateAuthz allows everything an ordinary session needs, and the termination resource
// only if `authority` says so.
type terminateAuthz struct{ authority bool }

func (a terminateAuthz) CheckAccess(_ context.Context, _ []string, resource, _ string) (bool, string, error) {
	if strings.HasPrefix(resource, application.SessionTerminateResourcePrefix) {
		return a.authority, "no policy to terminate", nil
	}
	return true, "allow policy matched", nil
}

func terminateService(authz application.AuthorizationClient) *application.SessionBrokerService {
	return application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), authz, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
}

func openOverHTTP(t *testing.T, svc *application.SessionBrokerService) string {
	t.Helper()
	rec := send(svc, http.MethodPost, "/sessions", `{"requestedBy":"alice","actorRoles":["dba"],"targetAccountId":"acc1","protocol":"ssh","justification":"routine","durationMinutes":20}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("open: %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out["id"] == nil {
		t.Fatalf("open: no id in %s", rec.Body.String())
	}
	return out["id"].(string)
}

func TestTerminateOverHTTP_TheCallerIsTheBodyTheGatewayBuilds_AndNothingElse(t *testing.T) {
	svc := terminateService(terminateAuthz{authority: false})
	id := openOverHTTP(t, svc)

	for name, body := range map[string]string{
		"no body":                   ``,
		"not JSON":                  `callerId=alice`,
		"an empty caller":           `{"callerId":""}`,
		"the field misspelled":      `{"caller":"alice"}`,
		"a field the client chose":  `{"requestedBy":"alice","decidedBy":"alice","actorRoles":["dba"]}`,
		"a body past the bound":     `{"callerId":"alice","actorRoles":["` + strings.Repeat("x", 1<<17) + `"]}`,
		"somebody else":             `{"callerId":"mallory","actorRoles":["dba"]}`,
		"somebody else with a role": `{"callerId":"mallory","actorRoles":["platform-admin","responder"]}`,
	} {
		t.Run(name, func(t *testing.T) {
			rec := send(svc, http.MethodDelete, "/sessions/"+id, body)
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%d %q, want 403", rec.Code, rec.Body.String())
			}
		})
	}
	if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("a refused termination changed the session: %s", rec.Body.String())
	}
	if rec := send(svc, http.MethodDelete, "/sessions/"+id, ``); !strings.Contains(rec.Body.String(), "authenticated user") {
		t.Fatalf("an absent caller is not told what is missing: %q", rec.Body.String())
	}
}

func TestTerminateOverHTTP_StatusCodes_AndWhoCan(t *testing.T) {
	svc := terminateService(terminateAuthz{authority: false})
	id := openOverHTTP(t, svc)

	if rec := send(svc, http.MethodDelete, "/sessions/session_nope", `{"callerId":"alice"}`); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown session: %d %q, want 404", rec.Code, rec.Body.String())
	}
	rec := send(svc, http.MethodDelete, "/sessions/"+id, `{"callerId":"alice","actorRoles":["dba"]}`)
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"terminated"`) {
		t.Fatalf("the requester: %d %q, want 200 and terminated", rec.Code, rec.Body.String())
	}
	if rec := send(svc, http.MethodDelete, "/sessions/"+id, `{"callerId":"alice"}`); rec.Code != http.StatusConflict {
		t.Fatalf("a second termination: %d, want 409", rec.Code)
	}
	if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"status":"terminated"`) {
		t.Fatalf("the session is not shown as terminated: %s", rec.Body.String())
	}

	// With an authority the Broker has no reason to refuse a person who is not the requester.
	withAuthority := terminateService(terminateAuthz{authority: true})
	id2 := openOverHTTP(t, withAuthority)
	if rec := send(withAuthority, http.MethodDelete, "/sessions/"+id2, `{"callerId":"responder","actorRoles":["responder"]}`); rec.Code != http.StatusOK {
		t.Fatalf("an authority: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

// A dependency that does not answer is a 503 — nothing was ended, and the client can try
// again — and its own message stays in the Broker's log: it can carry an address.
func TestTerminateOverHTTP_ADependencyFailureIsA503_WithoutItsMessage(t *testing.T) {
	previous := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	store := infrastructure.NewInMemoryStore()
	good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	id := openOverHTTP(t, good)
	down := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})

	assertUnavailableWithoutLeak(t, send(down, http.MethodDelete, "/sessions/"+id, `{"callerId":"mallory","actorRoles":["dba"]}`))
	// What the client is not told, the operator is: which session, and why.
	if !strings.Contains(logged.String(), "termination of "+id+" not made") || !strings.Contains(logged.String(), leak) {
		t.Fatalf("the failure is not in the Broker's log, with its cause: %q", logged.String())
	}
	if rec := send(good, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("a termination nobody could authorise was made: %s", rec.Body.String())
	}
	// The requester does not need the Authorization Service to end their own session.
	if rec := send(down, http.MethodDelete, "/sessions/"+id, `{"callerId":"alice","actorRoles":["dba"]}`); rec.Code != http.StatusOK {
		t.Fatalf("the requester with the Authorization Service down: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

// recordingAuthz remembers what it was asked, and allows the termination resource.
type recordingAuthz struct {
	roles            []string
	resource, action string
	asked            int
}

func (a *recordingAuthz) CheckAccess(_ context.Context, roles []string, resource, action string) (bool, string, error) {
	if strings.HasPrefix(resource, application.SessionTerminateResourcePrefix) {
		a.roles, a.resource, a.action = roles, resource, action
		a.asked++
	}
	return true, "allow policy matched", nil
}

// What the Authorization Service is asked is what the Gateway wrote in the body — the roles of
// the verified token — about the account of the session, and about terminating. (The service
// decides on the resource today and ignores the action: this pins what the Broker says, so a
// policy that one day looks at the action is asked the right question.)
func TestTerminateOverHTTP_AuthorizationIsAskedWithTheRolesOfTheBody_AboutTheAccountOfTheSession(t *testing.T) {
	authz := &recordingAuthz{}
	svc := terminateService(authz)
	id := openOverHTTP(t, svc)

	rec := send(svc, http.MethodDelete, "/sessions/"+id, `{"callerId":"responder","actorRoles":["responder","oncall"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %q, want 200", rec.Code, rec.Body.String())
	}
	if authz.asked != 1 {
		t.Fatalf("Authorization asked %d times, want once", authz.asked)
	}
	if strings.Join(authz.roles, ",") != "responder,oncall" {
		t.Fatalf("Authorization was asked with roles %v, want the ones of the body", authz.roles)
	}
	if want := application.SessionTerminateResourcePrefix + "acc1"; authz.resource != want {
		t.Fatalf("Authorization was asked about %q, want %q", authz.resource, want)
	}
	if authz.action != "session:terminate" {
		t.Fatalf("Authorization was asked about the action %q, want session:terminate", authz.action)
	}

	// The requester is not asked at all.
	authz2 := &recordingAuthz{}
	svc2 := terminateService(authz2)
	id2 := openOverHTTP(t, svc2)
	if rec := send(svc2, http.MethodDelete, "/sessions/"+id2, `{"callerId":"alice","actorRoles":["dba"]}`); rec.Code != http.StatusOK || authz2.asked != 0 {
		t.Fatalf("the requester: %d, Authorization asked %d times, want 200 and none", rec.Code, authz2.asked)
	}
}

// downProxy is a proxy that cannot be told (ADR-0018): its error names an address.
type downProxy struct{ failingProxy }

func (downProxy) RevokeSession(context.Context, string, time.Duration) error { return errors.New(leak) }

// If the proxy cannot be told, the session is not ended: a 503 that says nothing of the proxy,
// the cause in the Broker's log, the session still active — and the same call works when the
// proxy is back.
func TestTerminateOverHTTP_AProxyThatCannotBeToldIsA503_NothingIsEnded_AndTheCauseIsInTheLog(t *testing.T) {
	previous := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	store := infrastructure.NewInMemoryStore()
	good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	id := openOverHTTP(t, good)
	down := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, downProxy{})

	assertUnavailableWithoutLeak(t, send(down, http.MethodDelete, "/sessions/"+id, `{"callerId":"alice","actorRoles":["dba"]}`))
	if !strings.Contains(logged.String(), "termination of "+id+" not made") || !strings.Contains(logged.String(), leak) {
		t.Fatalf("the cause is not in the Broker's log: %q", logged.String())
	}
	if rec := send(good, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), `"status":"active"`) {
		t.Fatalf("a session the proxy could not be told about was marked ended: %s", rec.Body.String())
	}
	if rec := send(good, http.MethodDelete, "/sessions/"+id, `{"callerId":"alice","actorRoles":["dba"]}`); rec.Code != http.StatusOK {
		t.Fatalf("the same call with the proxy back: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

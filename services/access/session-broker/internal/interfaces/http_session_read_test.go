package interfaces_test

// Reading a session over HTTP (ADR-0019): the Broker takes the caller from the query the
// Gateway builds, and only from there; the codes say whether the session, the caller or a
// dependency is the reason; the refusal says nothing of the session; and a dependency's own
// message stays in the log.

import (
	"bytes"
	"context"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// readAuthz allows everything an ordinary session needs, and the read resource only if
// `reader` says so; it remembers what it was asked about the read.
type readAuthz struct {
	reader   bool
	roles    []string
	resource string
	action   string
	asked    int
}

func (a *readAuthz) CheckAccess(_ context.Context, roles []string, resource, action string) (bool, string, error) {
	if strings.HasPrefix(resource, application.SessionReadResourcePrefix) {
		a.roles, a.resource, a.action = roles, resource, action
		a.asked++
		return a.reader, "no policy to read the sessions of acc1", nil
	}
	return true, "allow policy matched", nil
}

func TestReadOverHTTP_TheCallerIsTheQueryTheGatewayBuilds_AndNothingElse(t *testing.T) {
	svc := terminateService(&readAuthz{reader: false})
	id := openOverHTTP(t, svc)

	for name, query := range map[string]string{
		"no query":                     "",
		"an empty caller":              "?callerId=",
		"only roles":                   "?actorRoles=platform-admin,auditor",
		"the field misspelled":         "?caller=alice",
		"somebody else":                "?callerId=mallory",
		"somebody else with roles":     "?callerId=mallory&actorRoles=platform-admin,auditor,responder",
		"the requester's name in case": "?callerId=ALICE",
		"the requester's name padded":  "?callerId=alice%20",
	} {
		t.Run(name, func(t *testing.T) {
			rec := send(svc, http.MethodGet, "/sessions/"+id+query, "")
			if rec.Code != http.StatusForbidden {
				t.Fatalf("%d %q, want 403", rec.Code, rec.Body.String())
			}
		})
	}
	// A caller nobody named is told what is missing; a caller who is named but may not read is
	// told nothing of the session.
	if rec := send(svc, http.MethodGet, "/sessions/"+id, ""); !strings.Contains(rec.Body.String(), "authenticated user") {
		t.Fatalf("an absent caller is not told what is missing: %q", rec.Body.String())
	}
	// A body is not a caller: the Gateway's read has none, and nothing in it is looked at.
	if rec := send(svc, http.MethodGet, "/sessions/"+id, `{"callerId":"alice","requestedBy":"alice"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("a caller sent in the body of a read: %d, want 403", rec.Code)
	}
}

func TestReadOverHTTP_StatusCodes_AndWhoCan(t *testing.T) {
	svc := terminateService(&readAuthz{reader: false})
	id := openOverHTTP(t, svc)

	if rec := send(svc, http.MethodGet, "/sessions/session_nope?callerId=alice", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("an unknown session: %d %q, want 404", rec.Code, rec.Body.String())
	}
	rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=alice&actorRoles=dba", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"status":"active"`) ||
		!strings.Contains(rec.Body.String(), `"id":"`+id+`"`) {
		t.Fatalf("the requester: %d %q, want 200 and the session", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("Content-Type %q, want application/json", ct)
	}

	// With a policy the Broker has no reason to refuse a person who is not the requester.
	allowed := terminateService(&readAuthz{reader: true})
	id2 := openOverHTTP(t, allowed)
	if rec := send(allowed, http.MethodGet, "/sessions/"+id2+"?callerId=auditor&actorRoles=auditor", ""); rec.Code != http.StatusOK {
		t.Fatalf("a reader with a policy: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

// What a refused caller reads says nothing of the session — nothing a guess of the id could
// turn into an account, a requester or a reason.
func TestReadOverHTTP_ARefusalSaysNothingOfTheSession(t *testing.T) {
	svc := terminateService(&readAuthz{reader: false})
	id := openOverHTTP(t, svc)

	rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=mallory&actorRoles=dba", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%d, want 403", rec.Code)
	}
	for _, secret := range []string{"alice", "acc1", "routine", "active", "ssh", "no policy to read", "expiresAt", id} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the refusal %q tells %q of the session", rec.Body.String(), secret)
		}
	}
	// Nor does the refusal of the same caller on an id that exists tell it apart, by status
	// line, from a body it can use: it is a 403, and unknown ids are the only 404.
	if rec2 := send(svc, http.MethodGet, "/sessions/session_nope?callerId=mallory", ""); rec2.Code != http.StatusNotFound {
		t.Fatalf("an unknown id for a stranger: %d, want 404 (the id space is the protection, ADR-0017)", rec2.Code)
	}
}

// What the Authorization Service is asked is what the Gateway wrote in the query — the roles
// of the verified token, comma-separated — about the account of the session, and about
// reading.
func TestReadOverHTTP_AuthorizationIsAskedWithTheRolesOfTheQuery_AboutTheAccountOfTheSession(t *testing.T) {
	authz := &readAuthz{reader: true}
	svc := terminateService(authz)
	id := openOverHTTP(t, svc)

	rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=auditor&actorRoles=auditor,secops", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %q, want 200", rec.Code, rec.Body.String())
	}
	if authz.asked != 1 {
		t.Fatalf("Authorization asked %d times, want once", authz.asked)
	}
	if strings.Join(authz.roles, "|") != "auditor|secops" {
		t.Fatalf("Authorization was asked with roles %q, want the two of the query, split on the comma", authz.roles)
	}
	if want := application.SessionReadResourcePrefix + "acc1"; authz.resource != want {
		t.Fatalf("Authorization was asked about %q, want %q", authz.resource, want)
	}
	if authz.action != "session:read" {
		t.Fatalf("Authorization was asked about the action %q, want session:read", authz.action)
	}

	// No roles in the query: none are claimed — the question is asked with an empty list.
	authz2 := &readAuthz{reader: false}
	svc2 := terminateService(authz2)
	id2 := openOverHTTP(t, svc2)
	if rec := send(svc2, http.MethodGet, "/sessions/"+id2+"?callerId=mallory", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("%d, want 403", rec.Code)
	}
	if len(authz2.roles) != 0 {
		t.Fatalf("roles %q were invented for a query that named none", authz2.roles)
	}

	// The requester is not asked at all.
	authz3 := &readAuthz{}
	svc3 := terminateService(authz3)
	id3 := openOverHTTP(t, svc3)
	if rec := send(svc3, http.MethodGet, "/sessions/"+id3+"?callerId=alice&actorRoles=dba", ""); rec.Code != http.StatusOK || authz3.asked != 0 {
		t.Fatalf("the requester: %d, Authorization asked %d times, want 200 and none", rec.Code, authz3.asked)
	}
}

// A dependency that does not answer is a 503 — nothing was refused for a reason, and the
// client can try again — and its own message stays in the Broker's log: it can carry an
// address. A failing store is not "no such session".
func TestReadOverHTTP_ADependencyFailureIsA503_WithoutItsMessage(t *testing.T) {
	previous := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	store := infrastructure.NewInMemoryStore()
	good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	id := openOverHTTP(t, good)

	t.Run("the Authorization Service is down", func(t *testing.T) {
		down := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
		assertUnavailableWithoutLeak(t, send(down, http.MethodGet, "/sessions/"+id+"?callerId=mallory&actorRoles=dba", ""))
		// What the client is not told, the operator is: which session, and why.
		if !strings.Contains(logged.String(), "reading session "+id+" not done") || !strings.Contains(logged.String(), leak) {
			t.Fatalf("the failure is not in the Broker's log, with its cause: %q", logged.String())
		}
		// The requester does not need the Authorization Service to read their own session.
		if rec := send(down, http.MethodGet, "/sessions/"+id+"?callerId=alice&actorRoles=dba", ""); rec.Code != http.StatusOK {
			t.Fatalf("the requester with the Authorization Service down: %d %q, want 200", rec.Code, rec.Body.String())
		}
	})
	t.Run("the store does not answer", func(t *testing.T) {
		logged.Reset()
		broken := application.NewSessionBrokerService(readsFail{store}, allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
		rec := send(broken, http.MethodGet, "/sessions/"+id+"?callerId=alice&actorRoles=dba", "")
		assertUnavailableWithoutLeak(t, rec)
		if strings.Contains(rec.Body.String(), "not found") {
			t.Fatalf("a failing store is reported as a missing session: %q", rec.Body.String())
		}
		if !strings.Contains(logged.String(), "reading session "+id+" not done") || !strings.Contains(logged.String(), leak) {
			t.Fatalf("the failure is not in the Broker's log, with its cause: %q", logged.String())
		}
	})
}

// readsFail is a store whose reads fail with an error that names an address.
type readsFail struct{ domain.SessionRepository }

func (readsFail) Get(context.Context, string) (*domain.Session, error) {
	return nil, errors.New(leak)
}

// Reading is read-only: the method decides, and a read leaves the session as it was.
func TestReadOverHTTP_ReadingChangesNothing_AndOtherMethodsAreNotReads(t *testing.T) {
	svc := terminateService(&readAuthz{reader: false})
	id := openOverHTTP(t, svc)
	path := "/sessions/" + id + "?callerId=alice&actorRoles=dba"

	first := send(svc, http.MethodGet, path, "")
	for i := 0; i < 3; i++ {
		again := send(svc, http.MethodGet, path, "")
		if again.Code != http.StatusOK || again.Body.String() != first.Body.String() {
			t.Fatalf("a second read differs: %d %q vs %q", again.Code, again.Body.String(), first.Body.String())
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodPatch, http.MethodPost} {
		var rec *httptest.ResponseRecorder = send(svc, m, path, "")
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d, want 405", m, rec.Code)
		}
	}
}

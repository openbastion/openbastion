package interfaces_test

// A refused read over HTTP is on the record (ADR-0020): under the caller the Gateway named
// in the query, about the session that was read, within the budget of that caller — and the
// answer is the same refusal whether or not its event was written. A read that is served to
// the requester, a session that does not exist, a request that names nobody and a dependency
// that does not answer write no refusal; a read served to a policy holder is an event of its
// own (ADR-0021), told apart here by its outcome.

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type heardEvent struct {
	actor, action, resourceType, resourceID string
	success                                 bool
}

// heardAudit remembers every event it is given.
type heardAudit struct {
	mu     sync.Mutex
	events []heardEvent
}

func (a *heardAudit) EmitEvent(_ context.Context, actor, action, resourceType, resourceID string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.events = append(a.events, heardEvent{actor, action, resourceType, resourceID, success})
	return nil
}

func (a *heardAudit) reads() []heardEvent {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []heardEvent
	for _, e := range a.events {
		if e.action == "session.read" {
			out = append(out, e)
		}
	}
	return out
}

// refusals are the reads that were refused (ADR-0020); served are the ones that were served
// to somebody who holds a policy (ADR-0021).
func (a *heardAudit) refusals() []heardEvent { return a.byOutcome(false) }
func (a *heardAudit) served() []heardEvent   { return a.byOutcome(true) }

func (a *heardAudit) byOutcome(success bool) []heardEvent {
	var out []heardEvent
	for _, e := range a.reads() {
		if e.success == success {
			out = append(out, e)
		}
	}
	return out
}

func serviceHearing(audit *heardAudit, authz application.AuthorizationClient) *application.SessionBrokerService {
	return application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), authz, okVault{}, audit, oneAccount{}, failingProxy{})
}

func TestReadRefusalOverHTTP_IsOnTheRecordUnderTheCallerOfTheQuery(t *testing.T) {
	audit := &heardAudit{}
	svc := serviceHearing(audit, &readAuthz{reader: false})
	id := openOverHTTP(t, svc)

	rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=mallory&actorRoles=dba", "")
	if rec.Code != http.StatusForbidden {
		t.Fatalf("%d, want 403", rec.Code)
	}
	got := audit.reads()
	want := heardEvent{actor: "mallory", action: "session.read", resourceType: "session", resourceID: id, success: false}
	if len(got) != 1 || got[0] != want {
		t.Fatalf("the audit heard %+v, want exactly %+v: the author is the caller the Gateway named, the subject the session read", got, want)
	}
}

func TestReadRefusalOverHTTP_WhatIsNotARefusalIsNotOne(t *testing.T) {
	audit := &heardAudit{}
	svc := serviceHearing(audit, &readAuthz{reader: true})
	id := openOverHTTP(t, svc)

	for name, c := range map[string]struct {
		path string
		want int
	}{
		"the requester":      {"/sessions/" + id + "?callerId=alice", http.StatusOK},
		"a policy":           {"/sessions/" + id + "?callerId=auditor&actorRoles=auditor", http.StatusOK},
		"an unknown session": {"/sessions/session_nope?callerId=mallory", http.StatusNotFound},
		"nobody named":       {"/sessions/" + id, http.StatusForbidden},
		"an empty caller":    {"/sessions/" + id + "?callerId=", http.StatusForbidden},
	} {
		t.Run(name, func(t *testing.T) {
			if rec := send(svc, http.MethodGet, c.path, ""); rec.Code != c.want {
				t.Fatalf("%d, want %d", rec.Code, c.want)
			}
		})
	}
	if got := audit.refusals(); len(got) != 0 {
		t.Fatalf("the audit heard %+v as refusals for reads that were not", got)
	}
	// ... and of these only the read served to a policy holder is an event, as a served read.
	if got := audit.served(); len(got) != 1 || got[0].actor != "auditor" || got[0].resourceID != id {
		t.Fatalf("the audit heard %+v as served reads, want only the policy holder's", got)
	}

	t.Run("a dependency that does not answer", func(t *testing.T) {
		store := infrastructure.NewInMemoryStore()
		good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, audit, oneAccount{}, failingProxy{})
		id2 := openOverHTTP(t, good)
		bad := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, audit, oneAccount{}, failingProxy{})
		if rec := send(bad, http.MethodGet, "/sessions/"+id2+"?callerId=mallory&actorRoles=dba", ""); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d, want 503", rec.Code)
		}
		if got := audit.refusals(); len(got) != 0 {
			t.Fatalf("the audit heard %+v for a read nobody could decide", got)
		}
		if got := audit.served(); len(got) != 1 {
			t.Fatalf("the audit heard %+v as served reads, want still the one", got)
		}
	})
}

// A budget bounds what is written, not what is answered.
func TestReadRefusalOverHTTP_TheAnswerIsTheSame_WhateverTheBudgetSays(t *testing.T) {
	audit := &heardAudit{}
	svc := serviceHearing(audit, &readAuthz{reader: false}).WithReadRefusalAudit(1, 6)
	id := openOverHTTP(t, svc)
	path := "/sessions/" + id + "?callerId=mallory&actorRoles=dba"

	first := send(svc, http.MethodGet, path, "")
	second := send(svc, http.MethodGet, path, "")
	if first.Code != http.StatusForbidden || second.Code != http.StatusForbidden || first.Body.String() != second.Body.String() {
		t.Fatalf("%d %q then %d %q: the refusal must be the same once the budget is spent", first.Code, first.Body.String(), second.Code, second.Body.String())
	}
	if got := audit.reads(); len(got) != 1 {
		t.Fatalf("%d written out of 2 with a burst of 1", len(got))
	}
}

// A read served to a policy holder is on the record before it is served, under the caller of
// the query (ADR-0021) — whatever roles the query claims — and is on the record each time.
func TestReadServedOverHTTP_IsOnTheRecordUnderTheCallerOfTheQuery_EachTime(t *testing.T) {
	audit := &heardAudit{}
	svc := serviceHearing(audit, &readAuthz{reader: true})
	id := openOverHTTP(t, svc)

	for i := 0; i < 3*application.DefaultReadAuditBurst; i++ {
		if rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=auditor&actorRoles=auditor", ""); rec.Code != http.StatusOK {
			t.Fatalf("read %d: %d %q, want 200", i, rec.Code, rec.Body.String())
		}
	}
	got := audit.served()
	if len(got) != 3*application.DefaultReadAuditBurst {
		t.Fatalf("%d event(s) for %d served reads: none is left out", len(got), 3*application.DefaultReadAuditBurst)
	}
	want := heardEvent{actor: "auditor", action: "session.read", resourceType: "session", resourceID: id, success: true}
	for _, e := range got {
		if e != want {
			t.Fatalf("the event is %+v, want %+v", e, want)
		}
	}
	if rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=alice&actorRoles=dba", ""); rec.Code != http.StatusOK {
		t.Fatalf("the requester: %d", rec.Code)
	}
	if n := len(audit.served()); n != 3*application.DefaultReadAuditBurst {
		t.Fatalf("%d event(s) after the requester read their own session, want still %d", n, 3*application.DefaultReadAuditBurst)
	}
}

// A read that cannot be recorded is a 503 that tells nothing of the session or of the audit —
// the cause stays in the Broker's log — while the requester still reads their own session and
// a refusal is still a refusal.
func TestReadServedOverHTTP_WithoutItsEventIsA503_WithoutTheCauseOrTheSession(t *testing.T) {
	previous := log.Writer()
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	down := &leakyAudit{}
	store := infrastructure.NewInMemoryStore()
	open := application.NewSessionBrokerService(store, &readAuthz{reader: true}, okVault{}, quietAudit{}, oneAccount{}, failingProxy{})
	id := openOverHTTP(t, open)
	svc := application.NewSessionBrokerService(store, &readAuthz{reader: true}, okVault{}, down, oneAccount{}, failingProxy{})
	refusing := application.NewSessionBrokerService(store, &readAuthz{reader: false}, okVault{}, down, oneAccount{}, failingProxy{})
	down.failing = true

	rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=auditor&actorRoles=auditor", "")
	assertUnavailableWithoutLeak(t, rec)
	for _, secret := range []string{"alice", "acc1", "routine", id} {
		if strings.Contains(rec.Body.String(), secret) {
			t.Fatalf("the 503 tells %q of a session that was not served: %q", secret, rec.Body.String())
		}
	}
	if !strings.Contains(logged.String(), "reading session "+id+" not done") || !strings.Contains(logged.String(), leak) {
		t.Fatalf("the failure is not in the Broker's log, with its cause: %q", logged.String())
	}
	if rec := send(svc, http.MethodGet, "/sessions/"+id+"?callerId=alice&actorRoles=dba", ""); rec.Code != http.StatusOK {
		t.Fatalf("the requester with the audit down: %d %q, want 200", rec.Code, rec.Body.String())
	}
	if rec := send(refusing, http.MethodGet, "/sessions/"+id+"?callerId=mallory&actorRoles=dba", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("a refusal with the audit down: %d %q, want 403", rec.Code, rec.Body.String())
	}
}

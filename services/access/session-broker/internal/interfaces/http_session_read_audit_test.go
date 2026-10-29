package interfaces_test

// A refused read over HTTP is on the record (ADR-0020): under the caller the Gateway named
// in the query, about the session that was read, within the budget of that caller — and the
// answer is the same refusal whether or not its event was written. A read that is served, a
// session that does not exist, a request that names nobody and a dependency that does not
// answer write nothing.

import (
	"context"
	"net/http"
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

func TestReadRefusalOverHTTP_WhatIsNotARefusalWritesNothing(t *testing.T) {
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
	if got := audit.reads(); len(got) != 0 {
		t.Fatalf("the audit heard %+v for reads that were not refusals", got)
	}

	t.Run("a dependency that does not answer", func(t *testing.T) {
		store := infrastructure.NewInMemoryStore()
		good := application.NewSessionBrokerService(store, allowAuthz{}, okVault{}, audit, oneAccount{}, failingProxy{})
		id2 := openOverHTTP(t, good)
		bad := application.NewSessionBrokerService(store, downAuthz{}, okVault{}, audit, oneAccount{}, failingProxy{})
		if rec := send(bad, http.MethodGet, "/sessions/"+id2+"?callerId=mallory&actorRoles=dba", ""); rec.Code != http.StatusServiceUnavailable {
			t.Fatalf("%d, want 503", rec.Code)
		}
		if got := audit.reads(); len(got) != 0 {
			t.Fatalf("the audit heard %+v for a read nobody could decide", got)
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

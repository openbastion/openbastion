package interfaces_test

// Ending a session through the Gateway (ADR-0017): the Broker is told who asks and with
// which roles, by the Gateway alone; and, since a refusal of somebody who may not end a
// session is an audit event each time, the call is charged to the user's action budget.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSessionTerminate_TheBrokerIsToldWhoAsksAndWithWhichRoles_NotTheClient(t *testing.T) {
	gw, broker := sessionGateway(t)

	forged := `{"callerId":"u-the-cto","requestedBy":"u-alice","actorRoles":["platform-admin","responder"]}`
	rec := do(gw, http.MethodDelete, "/sessions/s-1?callerId=u-the-cto&actorRoles=platform-admin", forged, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("terminate: %d %s", rec.Code, rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 || got[0].method != http.MethodDelete || got[0].path != "/sessions/s-1" {
		t.Fatalf("the Broker saw %+v", got)
	}
	if got[0].query != "" {
		t.Fatalf("the client's query reached the Broker: %q", got[0].query)
	}
	body := got[0].body
	if len(body) != 2 || body["callerId"] != "u-alice" {
		t.Fatalf("the Broker was told %v, want exactly the verified user and the roles of the token", body)
	}
	roles, _ := body["actorRoles"].([]any)
	if len(roles) != 2 || roles[0] != "sre" || roles[1] != "breakglass-requester" {
		t.Fatalf("the roles sent are %v, want those of the token — never the client's", roles)
	}
}

func TestSessionTerminate_WithoutATokenNothingReachesTheBroker(t *testing.T) {
	gw, broker := sessionGateway(t)
	if rec := do(gw, http.MethodDelete, "/sessions/s-1", `{"callerId":"u-the-cto"}`, false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec.Code)
	}
	if got := broker.requests(); len(got) != 0 {
		t.Fatalf("a request with no token reached the Broker: %+v", got)
	}
}

// One bucket for the four actions, in both directions: whichever is used first, the others
// share what is left — changing route is not a way to a fresh budget.
func TestSessionTerminate_IsChargedToTheOneBucketOfTheActions(t *testing.T) {
	t.Run("ending sessions spends what approve and connect would have used", func(t *testing.T) {
		gw, broker, _ := actionGateway(t, 3, 6, 100)
		var recs []*httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			recs = append(recs, doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", ""))
		}
		recs = append(recs,
			doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-2", ""),
			doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", ""),
			doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""))
		if got := codes(recs...); got != "[200 200 200 429 429 429]" {
			t.Fatalf("%s, want a burst of 3 shared by terminate, approve and connect", got)
		}
		if n := broker.reached(http.MethodDelete, "/s-1") + broker.reached(http.MethodDelete, "/s-2"); n != 3 {
			t.Fatalf("%d terminations reached the Broker, want 3: what the budget refuses must cost it nothing", n)
		}
	})
	t.Run("approve and connect spend what ending a session would have used", func(t *testing.T) {
		gw, broker, _ := actionGateway(t, 2, 6, 100)
		recs := []*httptest.ResponseRecorder{
			doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", ""),
			doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""),
			doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", ""),
		}
		if got := codes(recs...); got != "[200 200 429]" {
			t.Fatalf("%s, want the termination refused by the budget the other two spent", got)
		}
		if n := broker.reached(http.MethodDelete, "/s-1"); n != 0 {
			t.Fatalf("a refused termination reached the Broker %d time(s)", n)
		}
	})
}

func TestSessionTerminate_ARefusalSaysWhichBudget_WithATrueRetryAfter_AndTheBudgetRefills(t *testing.T) {
	gw, _, clock := actionGateway(t, 1, 6, 100)
	doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", "")
	refused := doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", "")
	if refused.Code != http.StatusTooManyRequests || refused.Header().Get("Retry-After") != "10" ||
		!strings.Contains(refused.Body.String(), "too many session actions from this user") {
		t.Fatalf("%d, Retry-After %q, %q; want 429, 10 and the action budget's own message",
			refused.Code, refused.Header().Get("Retry-After"), refused.Body.String())
	}
	clock.Advance(10 * time.Second)
	if rec := doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("after the 10 s that were announced: %d, want 200", rec.Code)
	}
}

// The budget is the user's, whichever session it is about and wherever the request comes from.
func TestSessionTerminate_TheBudgetIsTheUsersOwn(t *testing.T) {
	gw, _, _ := actionGateway(t, 1, 6, 100)
	a1 := doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", "10.0.0.2:5000")
	a2 := doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-2", "10.0.0.3:5000")
	b1 := doAs(gw, "tok-bob", http.MethodDelete, "/sessions/s-1", "10.0.0.2:5000")
	if got := codes(a1, a2, b1); got != "[200 429 200]" {
		t.Fatalf("%s, want Alice refused on her second termination whatever the session or address, and Bob not", got)
	}
}

// What is not an action stays free: reading the session, and a method that is not allowed.
func TestSessionTerminate_ReadingTheSessionAndAWrongMethodAreNotCharged(t *testing.T) {
	gw, _, _ := actionGateway(t, 1, 6, 100)
	doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", "")
	for i := 0; i < 5; i++ {
		if rec := doAs(gw, "tok-alice", http.MethodGet, "/sessions/s-1", ""); rec.Code != http.StatusOK {
			t.Fatalf("reading with the action budget spent: %d, want 200", rec.Code)
		}
	}
	for _, m := range []string{http.MethodPut, http.MethodPost, http.MethodPatch} {
		if rec := doAs(gw, "tok-bob", m, "/sessions/s-1", ""); rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s /sessions/s-1: %d, want 405", m, rec.Code)
		}
	}
	if rec := doAs(gw, "tok-bob", http.MethodDelete, "/sessions/s-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("Bob's first real termination: %d, want 200: a wrong method must not have been charged", rec.Code)
	}
}

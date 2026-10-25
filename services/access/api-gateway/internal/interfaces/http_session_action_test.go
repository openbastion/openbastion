package interfaces_test

// The per-user budget of approve, reject and connect (ADR-0016): the session actions that
// write on every call. What it is charged to, which routes it covers — and which it does not —
// what a refused action is told, and that it is not the budget of POST /sessions.

import (
	"bytes"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

// actionGateway has an action budget of `burst` and then `perMinute`, and a session-request
// budget of its own (`sessionBurst`), on a clock the test moves.
func actionGateway(t *testing.T, burst, perMinute, sessionBurst int) (http.Handler, *everythingBroker, *rateClock) {
	t.Helper()
	clock := &rateClock{t: time.Date(2026, 10, 25, 9, 0, 0, 0, time.UTC)}
	broker := newEverythingBroker(t)
	gw := newTestGateway(t, twoUsers(t).URL, broker.srv.URL).
		WithSessionActionLimiter(application.NewSessionActionLimiter(burst, perMinute).WithClock(clock.Now)).
		WithSessionRequestLimiter(application.NewSessionRequestLimiter(sessionBurst, 6).WithClock(clock.Now))
	return gw.Routes(), broker, clock
}

func doAs(gw http.Handler, token, method, path, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+token)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

// reached counts what the Broker saw for one method and path suffix.
func (b *everythingBroker) reached(method, suffix string) int {
	n := 0
	for _, r := range b.requests() {
		if r.method == method && strings.HasSuffix(r.path, suffix) {
			n++
		}
	}
	return n
}

var actionRoutes = []struct{ name, path string }{
	{"approve", "/sessions/s-1/approve"},
	{"reject", "/sessions/s-1/reject"},
	{"connect", "/sessions/s-1/connect"},
}

func TestSessionAction_ABurstThenRefused_ForEachOfTheThree_AndTheBrokerNeverSeesTheRefused(t *testing.T) {
	for _, route := range actionRoutes {
		t.Run(route.name, func(t *testing.T) {
			gw, broker, _ := actionGateway(t, 3, 6, 100)
			var recs []*httptest.ResponseRecorder
			for i := 0; i < 5; i++ {
				recs = append(recs, doAs(gw, "tok-alice", http.MethodPost, route.path, ""))
			}
			if got := codes(recs...); got != "[200 200 200 429 429]" {
				t.Fatalf("five %s with a burst of 3 gave %s", route.name, got)
			}
			if n := broker.reached(http.MethodPost, "/"+route.name); n != 3 {
				t.Fatalf("%d reached the Broker, want 3: a refused action must cost it nothing", n)
			}
			last := recs[4]
			if got := last.Header().Get("Retry-After"); got != "10" {
				t.Fatalf("Retry-After = %q, want 10 (one token every 10 s)", got)
			}
			body := last.Body.String()
			if !strings.Contains(body, "too many session actions from this user") || !strings.Contains(body, "at most 3 at once") || !strings.Contains(body, "retry in 10 s") {
				t.Fatalf("the refusal does not say which budget, the limit and the wait: %q", body)
			}
			if strings.Contains(body, "session requests") {
				t.Fatalf("the refusal is worded as the budget of POST /sessions: %q", body)
			}
		})
	}
}

// One bucket for the three: changing route is not a way to a fresh budget.
func TestSessionAction_IsOneBucketForTheThreeRoutes(t *testing.T) {
	gw, broker, _ := actionGateway(t, 3, 6, 100)
	var recs []*httptest.ResponseRecorder
	for _, route := range actionRoutes { // approve, reject, connect
		recs = append(recs, doAs(gw, "tok-alice", http.MethodPost, route.path, ""))
	}
	recs = append(recs,
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", ""),
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-2/reject", ""),
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-3/connect", ""))
	if got := codes(recs...); got != "[200 200 200 429 429 429]" {
		t.Fatalf("%s, want the three routes to share a burst of 3", got)
	}
	if n := len(broker.requests()); n != 3 {
		t.Fatalf("%d requests reached the Broker, want 3", n)
	}
}

// Asking for a session and then connecting to it is the ordinary pair: spending one budget
// must not take the other away.
func TestSessionAction_IsNotTheBudgetOfPostSessions(t *testing.T) {
	t.Run("actions spent, requests free", func(t *testing.T) {
		gw, _, _ := actionGateway(t, 1, 6, 100)
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", "")
		if rec := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("the action budget is not spent: %d", rec.Code)
		}
		if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusOK {
			t.Fatalf("POST /sessions after the actions were spent: %d, want 200", rec.Code)
		}
	})
	t.Run("requests spent, actions free", func(t *testing.T) {
		gw, _, _ := actionGateway(t, 5, 6, 1)
		postSession(gw, "tok-alice", validSessionBody, "")
		if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusTooManyRequests {
			t.Fatalf("the request budget is not spent: %d", rec.Code)
		}
		if rec := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""); rec.Code != http.StatusOK {
			t.Fatalf("connect after the requests were spent: %d, want 200: a user who asked too much must still reach the session they were given", rec.Code)
		}
	})
}

// The budget is the user's: not the address (the same for everybody behind the proxy), not
// the session it is about, not what is in the body.
func TestSessionAction_IsPerUser_NotPerAddressNorPerSession(t *testing.T) {
	gw, _, _ := actionGateway(t, 2, 6, 100)
	a1 := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", "10.0.0.2:5000")
	a2 := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-2/approve", "10.0.0.3:5000") // another address, another session
	a3 := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-3/approve", "10.0.0.4:5000")
	// Bob, from the address Alice used first, has his own.
	b1 := doAs(gw, "tok-bob", http.MethodPost, "/sessions/s-1/approve", "10.0.0.2:5000")
	b2 := doAs(gw, "tok-bob", http.MethodPost, "/sessions/s-1/approve", "10.0.0.2:5000")
	b3 := doAs(gw, "tok-bob", http.MethodPost, "/sessions/s-1/approve", "10.0.0.2:5000")
	if got := codes(a1, a2, a3, b1, b2, b3); got != "[200 200 429 200 200 429]" {
		t.Fatalf("%s: want each user to have a budget of 2, followed from address to address and from session to session", got)
	}
}

// What does not write on every call is not charged: terminate writes once per session, the
// reads write nothing, and a route that is not allowed or not found costs nothing.
func TestSessionAction_OnlyApproveRejectAndConnectAreCharged(t *testing.T) {
	gw, _, _ := actionGateway(t, 1, 6, 100)
	doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", "")
	if rec := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the budget is not spent: %d", rec.Code)
	}
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/sessions?status=pending_approval"},
		{http.MethodGet, "/sessions/s-1"},
		{http.MethodGet, "/sessions/s-1/recording"},
		{http.MethodDelete, "/sessions/s-1"},
	} {
		for i := 0; i < 5; i++ { // five of each: none may be refused for the action budget
			if rec := doAs(gw, "tok-alice", r.method, r.path, ""); rec.Code == http.StatusTooManyRequests {
				t.Fatalf("%s %s was refused for a budget that is about actions that write every time", r.method, r.path)
			}
		}
	}
	// A method that is not allowed, and an action that does not exist, are not charged either:
	// Bob has a budget of one, and these must leave it whole.
	for _, r := range []struct {
		method, path string
		want         int
	}{
		{http.MethodGet, "/sessions/s-1/approve", http.StatusMethodNotAllowed},
		{http.MethodGet, "/sessions/s-1/reject", http.StatusMethodNotAllowed},
		{http.MethodGet, "/sessions/s-1/connect", http.StatusMethodNotAllowed},
		{http.MethodPut, "/sessions/s-1/connect", http.StatusMethodNotAllowed},
		{http.MethodPost, "/sessions/s-1/teleport", http.StatusNotFound},
	} {
		if rec := doAs(gw, "tok-bob", r.method, r.path, ""); rec.Code != r.want {
			t.Fatalf("%s %s: %d, want %d", r.method, r.path, rec.Code, r.want)
		}
	}
	if rec := doAs(gw, "tok-bob", http.MethodPost, "/sessions/s-1/approve", ""); rec.Code != http.StatusOK {
		t.Fatalf("Bob's first real action: %d, want 200: what is not an action must not have been charged", rec.Code)
	}
}

func TestSessionAction_RetryAfterIsTrue_AndTheBudgetRefills(t *testing.T) {
	gw, _, clock := actionGateway(t, 1, 6, 100)
	doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/reject", "")
	first := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/reject", "")
	if first.Code != http.StatusTooManyRequests || first.Header().Get("Retry-After") != "10" {
		t.Fatalf("%d, Retry-After %q; want 429 and 10", first.Code, first.Header().Get("Retry-After"))
	}
	clock.Advance(6 * time.Second)
	second := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/reject", "")
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") != "4" {
		t.Fatalf("6 s later: %d, Retry-After %q; want 429 and 4", second.Code, second.Header().Get("Retry-After"))
	}
	clock.Advance(4 * time.Second)
	if rec := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/reject", ""); rec.Code != http.StatusOK {
		t.Fatalf("after the 10 s that were announced: %d, want 200", rec.Code)
	}
}

// A Gateway built by hand has the strict budget, and there is no way to switch it off.
func TestSessionAction_AGatewayBuiltByHandHasTheStrictDefault_AndNilDoesNotSwitchItOff(t *testing.T) {
	for name, build := range map[string]func(*interfaces.GatewayServer) *interfaces.GatewayServer{
		"default": func(g *interfaces.GatewayServer) *interfaces.GatewayServer { return g },
		"nil":     func(g *interfaces.GatewayServer) *interfaces.GatewayServer { return g.WithSessionActionLimiter(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			broker := newEverythingBroker(t)
			gw := build(newTestGateway(t, twoUsers(t).URL, broker.srv.URL)).Routes()
			ok := 0
			for i := 0; i < 15; i++ {
				if doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", "").Code == http.StatusOK {
					ok++
				}
			}
			if ok != application.DefaultSessionActionBurst || broker.reached(http.MethodPost, "/connect") != application.DefaultSessionActionBurst {
				t.Fatalf("%d of 15 actions passed (%d reached the Broker), want the default burst of %d", ok, broker.reached(http.MethodPost, "/connect"), application.DefaultSessionActionBurst)
			}
		})
	}
	t.Run("a nil limiter does not replace the one that was set", func(t *testing.T) {
		broker := newEverythingBroker(t)
		gw := newTestGateway(t, twoUsers(t).URL, broker.srv.URL).
			WithSessionActionLimiter(application.NewSessionActionLimiter(2, 6)).WithSessionActionLimiter(nil).Routes()
		var recs []*httptest.ResponseRecorder
		for i := 0; i < 4; i++ {
			recs = append(recs, doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", ""))
		}
		if got := codes(recs...); got != "[200 200 429 429]" {
			t.Fatalf("%s, want the budget of 2 that was set", got)
		}
	})
}

// The log says that somebody is being refused — once for each episode and each budget, not
// once for each request, and never the token.
func TestSessionAction_TheLogHasOneLinePerEpisode_NamesTheBudget_AndNeverTheToken(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	gw, _, clock := actionGateway(t, 1, 6, 1)
	doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", "")
	for i := 0; i < 20; i++ {
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", "")
	}
	lines := func() int { return strings.Count(logged.String(), "the session actions of user") }
	if n := lines(); n != 1 {
		t.Fatalf("%d log lines for 20 refused actions in a row, want 1:\n%s", n, logged.String())
	}
	if !strings.Contains(logged.String(), `"u-alice"`) || !strings.Contains(logged.String(), "more than 1 at once, then one every 10s") {
		t.Fatalf("the line does not say who and what limit: %s", logged.String())
	}
	clock.Advance(10 * time.Second)
	doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", "") // allowed again…
	for i := 0; i < 5; i++ {
		doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/approve", "") // …and refused again: a second episode
	}
	if n := lines(); n != 2 {
		t.Fatalf("%d log lines after a second episode, want 2", n)
	}
	// The other budget is another episode, with its own line and its own name.
	postSession(gw, "tok-alice", validSessionBody, "")
	postSession(gw, "tok-alice", validSessionBody, "")
	if n := strings.Count(logged.String(), "the session requests of user"); n != 1 {
		t.Fatalf("%d lines for the session-request budget, want 1:\n%s", n, logged.String())
	}
	if n := lines(); n != 2 {
		t.Fatalf("a refusal of POST /sessions was written as an action: %d lines", n)
	}
	if strings.Contains(logged.String(), "tok-alice") {
		t.Fatalf("a token is in the log:\n%s", logged.String())
	}
}

// What the Broker answers — whatever it is — is relayed as it was: the budget only decides
// whether the Broker is asked.
func TestSessionAction_WhatTheBrokerAnswersIsRelayedAsItIs(t *testing.T) {
	gw, _, _ := actionGateway(t, 3, 6, 100)
	rec := doAs(gw, "tok-alice", http.MethodPost, "/sessions/s-1/connect", "")
	if rec.Code != http.StatusOK || rec.Header().Get("Retry-After") != "" || strings.TrimSpace(rec.Body.String()) != `{"ok":true}` {
		t.Fatalf("%d, Retry-After %q, %q: an admitted action is the Broker's to answer", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
}

package interfaces_test

// Reading a session through the Gateway (ADR-0019): the Broker is told who asks and with
// which roles, by the Gateway alone; the answer of the Broker — a session, a refusal, a
// dependency that does not answer — is relayed as it is; and reading stays free of the
// action budget (ADR-0016, rule 1: the Gateway writes nothing for it; what the Broker records
// of a read is ADR-0020's and ADR-0021's).

import (
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"strings"
	"testing"
)

func TestSessionRead_TheBrokerIsToldWhoAsksAndWithWhichRoles_NotTheClient(t *testing.T) {
	gw, broker := sessionGateway(t)

	forged := "/sessions/s-1?callerId=u-the-requester&callerId=u-another&actorRoles=platform-admin,auditor&requestedBy=u-alice&evil=1"
	rec := do(gw, http.MethodGet, forged, `{"callerId":"u-the-cto","actorRoles":["platform-admin"]}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("read: %d %s", rec.Code, rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 || got[0].method != http.MethodGet || got[0].path != "/sessions/s-1" {
		t.Fatalf("the Broker saw %+v", got)
	}
	q, err := neturl.ParseQuery(got[0].query)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"callerId": "u-alice", "actorRoles": "sre,breakglass-requester"}
	if len(q) != len(want) {
		t.Fatalf("the Broker received the query %v, want exactly %v — nothing else of the client's", q, want)
	}
	for k, v := range want {
		if len(q[k]) != 1 || q[k][0] != v {
			t.Fatalf("query[%s] = %v, want %q (the verified token's, not the client's)", k, q[k], v)
		}
	}
	if len(got[0].body) != 0 {
		t.Fatalf("the client's body was relayed on a read: %v", got[0].body)
	}
}

// A role name is data, never query syntax: one that looks like a parameter stays a role.
func TestSessionRead_TheRolesOfTheTokenAreEncoded(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"sre", "x&callerId=u-victim"})
	t.Cleanup(authSrv.Close)
	broker := newEverythingBroker(t)
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL).Routes()

	if rec := do(gw, http.MethodGet, "/sessions/s-1", "", true); rec.Code != http.StatusOK {
		t.Fatalf("read: %d", rec.Code)
	}
	got := broker.requests()
	if len(got) != 1 {
		t.Fatalf("the Broker saw %+v", got)
	}
	q, err := neturl.ParseQuery(got[0].query)
	if err != nil {
		t.Fatal(err)
	}
	if len(q["callerId"]) != 1 || q["callerId"][0] != "u-alice" {
		t.Fatalf("callerId = %v: a role name became a parameter", q["callerId"])
	}
	if len(q["actorRoles"]) != 1 || q["actorRoles"][0] != "sre,x&callerId=u-victim" {
		t.Fatalf("actorRoles = %v, want the roles of the token, with their own characters", q["actorRoles"])
	}
}

func TestSessionRead_WithoutATokenNothingReachesTheBroker(t *testing.T) {
	gw, broker := sessionGateway(t)
	if rec := do(gw, http.MethodGet, "/sessions/s-1?callerId=u-alice", "", false); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d, want 401", rec.Code)
	}
	if got := broker.requests(); len(got) != 0 {
		t.Fatalf("a read with no token reached the Broker: %+v", got)
	}
}

// answeringBroker answers every request with one status and one body: what the Gateway does
// with a Broker's answer is what is looked at, whoever the caller is.
func answeringBroker(t *testing.T, status int, body string) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, body, status)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// Public refusals retain their service-defined reason. Internal upstream failures do not
// cross the Gateway boundary (ADR-0043).
func TestSessionRead_PublicRefusalsArePreservedAndUpstreamFailuresSanitized(t *testing.T) {
	for name, c := range map[string]struct {
		status int
		body   string
	}{
		"a refusal":            {http.StatusForbidden, "forbidden: this session is not yours to read"},
		"no such session":      {http.StatusNotFound, "session not found"},
		"a dependency is down": {http.StatusServiceUnavailable, "the session could not be read: a dependency is unavailable, try again shortly"},
		"an internal error":    {http.StatusInternalServerError, "boom"},
	} {
		t.Run(name, func(t *testing.T) {
			authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"sre"})
			t.Cleanup(authSrv.Close)
			gw := newTestGateway(t, authSrv.URL, answeringBroker(t, c.status, c.body)).Routes()

			rec := do(gw, http.MethodGet, "/sessions/s-1", "", true)
			wantStatus, wantBody := c.status, c.body
			if c.status >= http.StatusInternalServerError {
				wantStatus, wantBody = http.StatusServiceUnavailable, "upstream unavailable"
			}
			if rec.Code != wantStatus || !strings.Contains(rec.Body.String(), wantBody) {
				t.Fatalf("%d %q, want %d and %q", rec.Code, rec.Body.String(), wantStatus, wantBody)
			}
		})
	}
}

// A Broker nobody can reach is a Bad Gateway, said without an address.
func TestSessionRead_ABrokerThatCannotBeReachedIsA502_WithoutItsAddress(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"sre"})
	t.Cleanup(authSrv.Close)
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	gw := newTestGateway(t, authSrv.URL, url).Routes()

	rec := do(gw, http.MethodGet, "/sessions/s-1", "", true)
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("%d, want 502", rec.Code)
	}
	if strings.Contains(rec.Body.String(), "127.0.0.1") {
		t.Fatalf("the Broker's address is in the answer: %q", rec.Body.String())
	}
}

// Reading is not an action: as many reads as the client likes cost nothing of the budget,
// before or after it is spent (ADR-0016, rule 1).
func TestSessionRead_IsNotChargedToTheActionBudget(t *testing.T) {
	gw, broker, _ := actionGateway(t, 1, 6, 100)
	for i := 0; i < 10; i++ {
		if rec := doAs(gw, "tok-alice", http.MethodGet, "/sessions/s-1", ""); rec.Code != http.StatusOK {
			t.Fatalf("read %d: %d, want 200", i, rec.Code)
		}
	}
	if rec := doAs(gw, "tok-alice", http.MethodDelete, "/sessions/s-1", ""); rec.Code != http.StatusOK {
		t.Fatalf("the first action after ten reads: %d, want 200: reads must not have spent the budget", rec.Code)
	}
	if n := broker.reached(http.MethodGet, "/s-1"); n != 10 {
		t.Fatalf("%d reads reached the Broker, want 10", n)
	}
}

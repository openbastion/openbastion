package interfaces_test

// The session routes of the Gateway (ADR-0011): who is asking, who decides, and
// nothing that the Gateway does not know by name.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// everythingBroker records every request that reaches it, whatever the path: the
// claims that matter here are about what did NOT get through.
type everythingBroker struct {
	srv  *httptest.Server
	mu   sync.Mutex
	seen []seenRequest
}

type seenRequest struct {
	method, path string
	body         map[string]any
}

func newEverythingBroker(t *testing.T) *everythingBroker {
	t.Helper()
	b := &everythingBroker{}
	b.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		b.mu.Lock()
		b.seen = append(b.seen, seenRequest{r.Method, r.URL.EscapedPath(), body})
		b.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	t.Cleanup(b.srv.Close)
	return b
}

func (b *everythingBroker) requests() []seenRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]seenRequest(nil), b.seen...)
}

// sessionGateway is a Gateway whose verified user is u-alice with the roles of her token.
func sessionGateway(t *testing.T) (gw http.Handler, broker *everythingBroker) {
	t.Helper()
	authSrv := newFakeTokenVerifierServer(t, "tok-alice", "u-alice", "alice", []string{"sre", "breakglass-requester"})
	t.Cleanup(authSrv.Close)
	broker = newEverythingBroker(t)
	return newTestGateway(t, authSrv.URL, broker.srv.URL).Routes(), broker
}

func do(gw http.Handler, method, path, body string, authorised bool) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	if authorised {
		req.Header.Set("Authorization", "Bearer tok-alice")
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

// Only the requester connects: the Broker is told who is asking by the Gateway, from
// the verified token, and nothing the client writes can say otherwise.
func TestSessionRoutes_ConnectTellsTheBrokerWhoIsAsking_NotTheClient(t *testing.T) {
	gw, broker := sessionGateway(t)

	rec := do(gw, http.MethodPost, "/sessions/s-1/connect", `{"callerId":"u-the-requester","requestedBy":"u-the-requester"}`, true)
	if rec.Code != http.StatusOK {
		t.Fatalf("connect: %d %s", rec.Code, rec.Body.String())
	}
	got := broker.requests()
	if len(got) != 1 || got[0].path != "/sessions/s-1/connect" {
		t.Fatalf("the Broker saw %+v", got)
	}
	if len(got[0].body) != 1 || got[0].body["callerId"] != "u-alice" {
		t.Fatalf("the Broker was told %v, want exactly {callerId: u-alice} — the client's claim must not survive", got[0].body)
	}
}

// The decision is the verified user's, with the roles of the verified token. A client
// who writes another name, or an approval role, into the body gets neither.
func TestSessionRoutes_ADecisionIsTheVerifiedUsers_NotWhatTheClientClaims(t *testing.T) {
	for _, action := range []string{"approve", "reject"} {
		t.Run(action, func(t *testing.T) {
			gw, broker := sessionGateway(t)

			forged := `{"decidedBy":"u-the-cto","actorRoles":["breakglass-approver","platform-admin"],"requestedBy":"u-someone-else"}`
			rec := do(gw, http.MethodPost, "/sessions/s-1/"+action, forged, true)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s: %d %s", action, rec.Code, rec.Body.String())
			}
			got := broker.requests()
			if len(got) != 1 || got[0].path != "/sessions/s-1/"+action || got[0].method != http.MethodPost {
				t.Fatalf("the Broker saw %+v", got)
			}
			body := got[0].body
			if len(body) != 2 || body["decidedBy"] != "u-alice" {
				t.Fatalf("the Broker was told %v, want exactly the verified user", body)
			}
			roles, _ := body["actorRoles"].([]any)
			if len(roles) != 2 || roles[0] != "sre" || roles[1] != "breakglass-requester" {
				t.Fatalf("the roles sent are %v, want those of the token — never the client's", roles)
			}
		})
	}
}

// What the Gateway does not know by name does not reach the Broker: a route added
// there later is not relayed raw, with the client's body, by default.
func TestSessionRoutes_OnlyKnownRoutesReachTheBroker(t *testing.T) {
	for name, c := range map[string]struct {
		method, path string
		want         int
	}{
		"an unknown action": {http.MethodPost, "/sessions/s-1/evil", http.StatusNotFound},
		"a deeper path":     {http.MethodPost, "/sessions/s-1/approve/extra", http.StatusNotFound},
		"a trailing slash":  {http.MethodPost, "/sessions/s-1/", http.StatusNotFound},
		// The mux answers a non-canonical path with a redirect to the cleaned one; what
		// matters is that the request itself is not relayed.
		"a double slash after the id":       {http.MethodPost, "/sessions/s-1//approve", http.StatusMovedPermanently},
		"no id":                             {http.MethodPost, "/sessions//approve", http.StatusMovedPermanently},
		"approve by GET":                    {http.MethodGet, "/sessions/s-1/approve", http.StatusMethodNotAllowed},
		"reject by DELETE":                  {http.MethodDelete, "/sessions/s-1/reject", http.StatusMethodNotAllowed},
		"connect by GET":                    {http.MethodGet, "/sessions/s-1/connect", http.StatusMethodNotAllowed},
		"the session itself by POST":        {http.MethodPost, "/sessions/s-1", http.StatusMethodNotAllowed},
		"the session itself by PUT":         {http.MethodPut, "/sessions/s-1", http.StatusMethodNotAllowed},
		"the recording by POST":             {http.MethodPost, "/sessions/s-1/recording", http.StatusMethodNotAllowed},
		"an internal-looking action":        {http.MethodPost, "/sessions/s-1/internal", http.StatusNotFound},
		"a decision with a smuggled suffix": {http.MethodPost, "/sessions/s-1/approve%2Fx", http.StatusNotFound},
	} {
		t.Run(name, func(t *testing.T) {
			gw, broker := sessionGateway(t)
			rec := do(gw, c.method, c.path, `{"decidedBy":"u-the-cto"}`, true)
			if rec.Code != c.want {
				t.Fatalf("%s %s: %d, want %d", c.method, c.path, rec.Code, c.want)
			}
			if got := broker.requests(); len(got) != 0 {
				t.Fatalf("%s %s reached the Broker: %+v", c.method, c.path, got)
			}
		})
	}
}

// The control for the table above: the routes that ARE known get through.
func TestSessionRoutes_TheKnownRoutesReachTheBroker(t *testing.T) {
	for _, c := range []struct{ method, path string }{
		{http.MethodGet, "/sessions/s-1"}, {http.MethodDelete, "/sessions/s-1"},
		{http.MethodPost, "/sessions/s-1/connect"}, {http.MethodPost, "/sessions/s-1/approve"}, {http.MethodPost, "/sessions/s-1/reject"},
	} {
		gw, broker := sessionGateway(t)
		if rec := do(gw, c.method, c.path, `{}`, true); rec.Code != http.StatusOK {
			t.Fatalf("%s %s: %d", c.method, c.path, rec.Code)
		}
		if got := broker.requests(); len(got) != 1 || got[0].path != c.path || got[0].method != c.method {
			t.Fatalf("%s %s: the Broker saw %+v", c.method, c.path, got)
		}
	}
}

func TestSessionRoutes_ADecisionOrAConnectNeedsAToken(t *testing.T) {
	for _, path := range []string{"/sessions/s-1/approve", "/sessions/s-1/reject", "/sessions/s-1/connect"} {
		gw, broker := sessionGateway(t)
		if rec := do(gw, http.MethodPost, path, `{"decidedBy":"u-the-cto"}`, false); rec.Code != http.StatusUnauthorized {
			t.Fatalf("%s without a token: %d, want 401", path, rec.Code)
		}
		if got := broker.requests(); len(got) != 0 {
			t.Fatalf("%s without a token reached the Broker: %+v", path, got)
		}
	}
}

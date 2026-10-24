package interfaces_test

// The per-user budget of POST /sessions (ADR-0014): what it is charged to, what it counts,
// what a refused request is told and what it leaves behind.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

type rateClock struct{ t time.Time }

func (c *rateClock) Now() time.Time          { return c.t }
func (c *rateClock) Advance(d time.Duration) { c.t = c.t.Add(d) }

// twoUsers verifies two tokens: tok-alice is u-alice and tok-bob is u-bob.
func twoUsers(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		who := map[string][2]string{"tok-alice": {"u-alice", "alice"}, "tok-bob": {"u-bob", "bob"}}[req.Token]
		if who[0] == "" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"userId": who[0], "username": who[1], "roles": []string{"sre"}})
	})
	mux.HandleFunc("/auth/v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"accessToken":"tok-alice","expiresIn":3600}`))
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

// rateGateway has a session budget of `burst` and then `perMinute`, on a clock the test moves.
func rateGateway(t *testing.T, burst, perMinute int) (http.Handler, *everythingBroker, *rateClock) {
	t.Helper()
	clock := &rateClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	broker := newEverythingBroker(t)
	gw := newTestGateway(t, twoUsers(t).URL, broker.srv.URL).
		WithSessionRequestLimiter(application.NewSessionRequestLimiter(burst, perMinute).WithClock(clock.Now))
	return gw.Routes(), broker, clock
}

const validSessionBody = `{"targetAccountId":"acc1","protocol":"ssh","justification":"INC-1 recorder down","durationMinutes":10}`

func postSession(gw http.Handler, token, body, remoteAddr string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(body)))
	req.Header.Set("Authorization", "Bearer "+token)
	if remoteAddr != "" {
		req.RemoteAddr = remoteAddr
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func (b *everythingBroker) postsToSessions() int {
	n := 0
	for _, r := range b.requests() {
		if r.method == http.MethodPost && r.path == "/sessions" {
			n++
		}
	}
	return n
}

func TestSessionRate_ABurstThenRefused_AndTheBrokerNeverSeesTheRefused(t *testing.T) {
	gw, broker, _ := rateGateway(t, 3, 6)
	var codes []int
	var last *httptest.ResponseRecorder
	for i := 0; i < 5; i++ {
		last = postSession(gw, "tok-alice", validSessionBody, "")
		codes = append(codes, last.Code)
	}
	if fmt.Sprint(codes) != "[200 200 200 429 429]" {
		t.Fatalf("five requests with a burst of 3 gave %v", codes)
	}
	if n := broker.postsToSessions(); n != 3 {
		t.Fatalf("%d requests reached the Broker, want 3: a refused request must not cost it a row and an audit event", n)
	}
	if got := last.Header().Get("Retry-After"); got != "10" {
		t.Fatalf("Retry-After = %q, want 10 (one token every 10 s)", got)
	}
	if body := last.Body.String(); !strings.Contains(body, "at most 3 at once") || !strings.Contains(body, "retry in 10 s") {
		t.Fatalf("the refusal does not say the limit and the wait: %q", body)
	}
}

// What the budget is charged to is the user the token proves: not the address (the same for
// everybody behind the reverse proxy), and not what the body claims.
func TestSessionRate_IsPerUser_NotPerAddress_AndNotWhatTheBodyClaims(t *testing.T) {
	gw, broker, _ := rateGateway(t, 2, 6)
	const proxy = "192.0.2.10:4000" // what every user looks like behind the reverse proxy

	for i := 0; i < 2; i++ {
		if rec := postSession(gw, "tok-alice", validSessionBody, proxy); rec.Code != http.StatusOK {
			t.Fatalf("alice %d: %d", i+1, rec.Code)
		}
	}
	if rec := postSession(gw, "tok-alice", validSessionBody, proxy); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("alice's third: %d, want 429", rec.Code)
	}
	// Bob comes from the very same address and has a budget of his own.
	for i := 0; i < 2; i++ {
		if rec := postSession(gw, "tok-bob", validSessionBody, proxy); rec.Code != http.StatusOK {
			t.Fatalf("bob %d, from the address alice exhausted: %d, want 200", i+1, rec.Code)
		}
	}
	// Alice from another address is the same user: still refused.
	if rec := postSession(gw, "tok-alice", validSessionBody, "198.51.100.7:5000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("alice from another address: %d, want 429", rec.Code)
	}
	// And a body that says it is somebody else changes nothing about who pays.
	forged := `{"requestedBy":"u-bob","actorRoles":["admin"],"targetAccountId":"acc1","protocol":"ssh","justification":"INC-1 recorder down","durationMinutes":10}`
	if rec := postSession(gw, "tok-alice", forged, "198.51.100.8:5000"); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("alice claiming to be bob: %d, want 429 — the budget is charged to the verified user", rec.Code)
	}
	if rec := postSession(gw, "tok-bob", validSessionBody, proxy); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("bob's third: %d, want 429 — alice's forged request must not have been charged to him or refunded to her", rec.Code)
	}
	if n := broker.postsToSessions(); n != 4 {
		t.Fatalf("%d requests reached the Broker, want 4 (two each)", n)
	}
}

// It is the attempts that cost the Broker a row and an audit event, so every attempt is
// counted — and before the body is read, so that garbage costs as much as a good request.
func TestSessionRate_CountsEveryAttempt_BeforeTheBodyIsRead(t *testing.T) {
	gw, broker, _ := rateGateway(t, 2, 6)
	for i := 0; i < 2; i++ {
		if rec := postSession(gw, "tok-alice", "this is not json", ""); rec.Code != http.StatusBadRequest {
			t.Fatalf("garbage %d: %d, want 400", i+1, rec.Code)
		}
	}
	if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("a good request after two garbage ones: %d, want 429 — they were not free", rec.Code)
	}
	if rec := postSession(gw, "tok-alice", "this is not json", ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("garbage once the budget is spent: %d, want 429 — the limit comes before the body is read", rec.Code)
	}
	if n := broker.postsToSessions(); n != 0 {
		t.Fatalf("%d requests reached the Broker, want 0", n)
	}
}

// Retry-After is the truth, and following it works.
func TestSessionRate_RetryAfterIsTrue_AndTheBudgetRefills(t *testing.T) {
	gw, _, clock := rateGateway(t, 1, 6) // one token every 10 s
	if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusOK {
		t.Fatalf("first: %d", rec.Code)
	}
	rec := postSession(gw, "tok-alice", validSessionBody, "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("second: %d, Retry-After %q; want 429 and 10", rec.Code, rec.Header().Get("Retry-After"))
	}
	clock.Advance(4 * time.Second)
	rec = postSession(gw, "tok-alice", validSessionBody, "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "6" {
		t.Fatalf("4 s later: %d, Retry-After %q; want 429 and 6", rec.Code, rec.Header().Get("Retry-After"))
	}
	clock.Advance(6 * time.Second) // what Retry-After said
	if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusOK {
		t.Fatalf("after waiting what Retry-After said: %d, want 200", rec.Code)
	}
}

// Only the requests that create sessions are charged to this budget; everything else
// a user does with a session is not slowed by it.
func TestSessionRate_OnlyPostSessionsIsCharged(t *testing.T) {
	gw, _, _ := rateGateway(t, 1, 6)
	postSession(gw, "tok-alice", validSessionBody, "")
	if rec := postSession(gw, "tok-alice", validSessionBody, ""); rec.Code != http.StatusTooManyRequests {
		t.Fatalf("the budget is not spent: %d", rec.Code)
	}
	for _, r := range []struct{ method, path string }{
		{http.MethodGet, "/sessions?status=pending_approval"},
		{http.MethodGet, "/sessions/s-1"},
		{http.MethodPost, "/sessions/s-1/approve"},
		{http.MethodPost, "/sessions/s-1/reject"},
		{http.MethodPost, "/sessions/s-1/connect"},
		{http.MethodDelete, "/sessions/s-1"},
	} {
		req := httptest.NewRequest(r.method, r.path, strings.NewReader("{}"))
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if rec.Code == http.StatusTooManyRequests {
			t.Fatalf("%s %s was refused for a budget that is about creating sessions", r.method, r.path)
		}
	}
	// A request that is not allowed on this route at all is not charged either.
	req := httptest.NewRequest(http.MethodPut, "/sessions", nil)
	req.Header.Set("Authorization", "Bearer tok-bob")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("PUT /sessions: %d, want 405", rec.Code)
	}
}

// A Gateway built by hand has the strict budget, and there is no way to switch it off.
func TestSessionRate_AGatewayBuiltByHandHasTheStrictDefault_AndNilDoesNotSwitchItOff(t *testing.T) {
	for name, build := range map[string]func(*interfaces.GatewayServer) *interfaces.GatewayServer{
		"default": func(g *interfaces.GatewayServer) *interfaces.GatewayServer { return g },
		"nil":     func(g *interfaces.GatewayServer) *interfaces.GatewayServer { return g.WithSessionRequestLimiter(nil) },
	} {
		t.Run(name, func(t *testing.T) {
			broker := newEverythingBroker(t)
			gw := build(newTestGateway(t, twoUsers(t).URL, broker.srv.URL)).Routes()
			ok := 0
			for i := 0; i < 15; i++ {
				if postSession(gw, "tok-alice", validSessionBody, "").Code == http.StatusOK {
					ok++
				}
			}
			if ok != application.DefaultSessionBurst || broker.postsToSessions() != application.DefaultSessionBurst {
				t.Fatalf("%d of 15 requests passed (%d reached the Broker), want the default burst of %d", ok, broker.postsToSessions(), application.DefaultSessionBurst)
			}
		})
	}
}

// The log says that somebody is being refused — once for each episode, not once for each
// request: a flood must not be able to fill the log either.
func TestSessionRate_TheLogHasOneLinePerEpisode_AndNeverTheToken(t *testing.T) {
	var logged bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(previous) })

	gw, _, clock := rateGateway(t, 1, 6)
	postSession(gw, "tok-alice", validSessionBody, "")
	for i := 0; i < 20; i++ {
		postSession(gw, "tok-alice", validSessionBody, "")
	}
	lines := func() int { return strings.Count(logged.String(), "the session requests of user") }
	if n := lines(); n != 1 {
		t.Fatalf("%d log lines for 20 refused requests in a row, want 1:\n%s", n, logged.String())
	}
	if !strings.Contains(logged.String(), `"u-alice"`) || !strings.Contains(logged.String(), "more than 1 at once, then one every 10s") {
		t.Fatalf("the line does not say who and what limit: %s", logged.String())
	}
	clock.Advance(10 * time.Second)
	postSession(gw, "tok-alice", validSessionBody, "") // allowed again…
	for i := 0; i < 5; i++ {
		postSession(gw, "tok-alice", validSessionBody, "") // …and refused again: a second episode
	}
	if n := lines(); n != 2 {
		t.Fatalf("%d log lines after a second episode, want 2", n)
	}
	// Somebody else being refused is another line, with another name.
	postSession(gw, "tok-bob", validSessionBody, "")
	postSession(gw, "tok-bob", validSessionBody, "")
	if n := lines(); n != 3 || !strings.Contains(logged.String(), `"u-bob"`) {
		t.Fatalf("%d lines after bob was refused, want 3, and one naming him:\n%s", n, logged.String())
	}
	if strings.Contains(logged.String(), "tok-alice") || strings.Contains(logged.String(), "tok-bob") {
		t.Fatalf("a token is in the log:\n%s", logged.String())
	}
}

// A 429 that the Broker answered (the quota of ADR-0013) is relayed as it is: the Gateway
// does not invent a Retry-After for a limit that is not about time.
func TestSessionRate_TheBrokersOwn429IsRelayedWithoutARetryAfter(t *testing.T) {
	broker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "too many break-glass requests are waiting for a decision (at most 3 per requester)", http.StatusTooManyRequests)
	}))
	t.Cleanup(broker.Close)
	gw := newTestGateway(t, twoUsers(t).URL, broker.URL).Routes()
	rec := postSession(gw, "tok-alice", validSessionBody, "")
	if rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "" || !strings.Contains(rec.Body.String(), "waiting for a decision") {
		t.Fatalf("%d, Retry-After %q, %q", rec.Code, rec.Header().Get("Retry-After"), rec.Body.String())
	}
}

// The two limiters that were here before say the truth about when to come back, too: they
// used to answer "1" whatever the refill was.
func TestRateLimits_TheLoginAndTheAuthenticatedLimitersAlsoSayTheTruth(t *testing.T) {
	clock := &rateClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	auth := twoUsers(t)
	broker := newEverythingBroker(t)
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL},
		application.NewRateLimiter(1, time.Minute).WithClock(clock.Now), // authenticated traffic
		application.NewRateLimiter(2, time.Minute).WithClock(clock.Now), // login
		auth.URL, broker.srv.URL, "", "", "").Routes()

	login := func() *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"alice","password":"x"}`)))
		return rec
	}
	login()
	login()
	if rec := login(); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("login: %d, Retry-After %q; want 429 and 60", rec.Code, rec.Header().Get("Retry-After"))
	}
	clock.Advance(45 * time.Second)
	if rec := login(); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "15" {
		t.Fatalf("login 45 s later: %d, Retry-After %q; want 429 and 15", rec.Code, rec.Header().Get("Retry-After"))
	}

	get := func() *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/sessions/s-1", nil)
		req.Header.Set("Authorization", "Bearer tok-alice")
		rec := httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		return rec
	}
	get()
	if rec := get(); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "60" {
		t.Fatalf("authenticated: %d, Retry-After %q; want 429 and 60", rec.Code, rec.Header().Get("Retry-After"))
	}
}

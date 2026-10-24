package interfaces_test

// What the per-address limiters call "the client" (ADR-0015), at the HTTP surface: behind a
// declared reverse proxy each real client has its own bucket, and no client can choose
// its own key by writing X-Forwarded-For.

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

// addressGateway has `authBurst` authenticated requests and `loginBurst` login attempts per
// client address (and one more a minute, on a clock the test moves), and the given trust.
func addressGateway(t *testing.T, authBurst, loginBurst int, trust *application.ProxyTrust) (http.Handler, *rateClock) {
	t.Helper()
	clock := &rateClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	auth := twoUsers(t)
	broker := newEverythingBroker(t)
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL},
		application.NewRateLimiter(authBurst, time.Minute).WithClock(clock.Now),
		application.NewRateLimiter(loginBurst, time.Minute).WithClock(clock.Now),
		auth.URL, broker.srv.URL, "", "", "")
	if trust != nil {
		gw.WithProxyTrust(trust)
	}
	return gw.Routes(), clock
}

func mustTrust(t *testing.T, list string) *application.ProxyTrust {
	t.Helper()
	p, err := application.ParseTrustedProxies(list)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// loginFrom is a login attempt that arrives from the peer `peer`, carrying the given
// X-Forwarded-For lines.
func loginFrom(gw http.Handler, peer string, xff ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/auth/login", strings.NewReader(`{"username":"alice","password":"x"}`))
	req.RemoteAddr = peer
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func getFrom(gw http.Handler, token, peer string, xff ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "/sessions/s-1", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	req.RemoteAddr = peer
	for _, v := range xff {
		req.Header.Add("X-Forwarded-For", v)
	}
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	return rec
}

func codes(recs ...*httptest.ResponseRecorder) string {
	var out []int
	for _, r := range recs {
		out = append(out, r.Code)
	}
	return fmt.Sprint(out)
}

// The defect ADR-0014 measured, and what declaring the proxy changes: behind it, one user can
// drain the login burst of everybody.
func TestClientAddress_BehindADeclaredProxy_EachClientHasItsOwnLoginBucket(t *testing.T) {
	const proxy = "10.0.0.2:5000"
	t.Run("without the proxy declared, everybody shares the proxy's bucket", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, nil)
		a1 := loginFrom(gw, proxy, "203.0.113.9")
		a2 := loginFrom(gw, proxy, "203.0.113.9")
		b := loginFrom(gw, proxy, "198.51.100.4")
		if codes(a1, a2, b) != "[200 200 429]" {
			t.Fatalf("%s: a second client was refused because of the first only if the bucket is shared; want [200 200 429]", codes(a1, a2, b))
		}
	})
	t.Run("with it declared, each client has its own", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		a1 := loginFrom(gw, proxy, "203.0.113.9")
		a2 := loginFrom(gw, proxy, "203.0.113.9")
		a3 := loginFrom(gw, proxy, "203.0.113.9")
		b1 := loginFrom(gw, proxy, "198.51.100.4")
		b2 := loginFrom(gw, proxy, "198.51.100.4")
		b3 := loginFrom(gw, proxy, "198.51.100.4")
		if codes(a1, a2, a3, b1, b2, b3) != "[200 200 429 200 200 429]" {
			t.Fatalf("%s: want each client to have its burst of 2 and be refused on its third", codes(a1, a2, a3, b1, b2, b3))
		}
		if a3.Header().Get("Retry-After") != "60" {
			t.Fatalf("Retry-After = %q, want 60", a3.Header().Get("Retry-After"))
		}
	})
	t.Run("two addresses of one IPv6 /64 are one client", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		x1 := loginFrom(gw, proxy, "2001:db8:1:2::1")
		x2 := loginFrom(gw, proxy, "2001:db8:1:2:ffff::7")
		x3 := loginFrom(gw, proxy, "2001:db8:1:2:1234::9")
		y1 := loginFrom(gw, proxy, "2001:db8:1:3::1")
		if codes(x1, x2, x3, y1) != "[200 200 429 200]" {
			t.Fatalf("%s: want the third address of the same /64 refused and the next /64 untouched", codes(x1, x2, x3, y1))
		}
	})
}

// The point of the whole decision: the header is written by whoever sends the request, and a
// limit that believes it lets the sender have a new key with every request.
func TestClientAddress_ACannotChooseItsKey_ByWritingXForwardedFor(t *testing.T) {
	t.Run("from a peer that is not a declared proxy, the header is ignored", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		var recs []*httptest.ResponseRecorder
		for i := 1; i <= 6; i++ {
			recs = append(recs, loginFrom(gw, "203.0.113.9:4444", fmt.Sprintf("6.6.6.%d", i)))
		}
		if codes(recs...) != "[200 200 429 429 429 429]" {
			t.Fatalf("%s: rotating X-Forwarded-For from outside must not give a new bucket", codes(recs...))
		}
	})
	t.Run("from a declared proxy, what the client wrote on the left is not read", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		var recs []*httptest.ResponseRecorder
		for i := 1; i <= 6; i++ {
			// The proxy appended the address it saw, 203.0.113.9, to what the client sent.
			recs = append(recs, loginFrom(gw, "10.0.0.2:5000", fmt.Sprintf("6.6.6.%d, 203.0.113.9", i)))
		}
		if codes(recs...) != "[200 200 429 429 429 429]" {
			t.Fatalf("%s: a forged left side must not give a new bucket", codes(recs...))
		}
		// And a forged proxy next to the real client does not either.
		more := loginFrom(gw, "10.0.0.2:5000", "203.0.113.9, 10.0.0.77")
		if more.Code != http.StatusTooManyRequests {
			t.Fatalf("a proxy forged next to the client gave a new bucket: %d", more.Code)
		}
	})
	t.Run("the header may come on several lines: they are one chain", func(t *testing.T) {
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		var recs []*httptest.ResponseRecorder
		for i := 1; i <= 5; i++ {
			// A line the client wrote, then the line the proxy added.
			recs = append(recs, loginFrom(gw, "10.0.0.2:5000", fmt.Sprintf("6.6.6.%d", i), "203.0.113.9"))
		}
		if codes(recs...) != "[200 200 429 429 429]" {
			t.Fatalf("%s: the last line is the proxy's; a forged line before it must not give a new bucket", codes(recs...))
		}
		// And when the last line is only proxies, the walk goes on to the line before it.
		gw2, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		var more []*httptest.ResponseRecorder
		for i := 0; i < 3; i++ {
			more = append(more, loginFrom(gw2, "10.0.0.2:5000", "203.0.113.9", "10.0.0.3"))
		}
		if codes(more...) != "[200 200 429]" {
			t.Fatalf("%s: a last line of proxies must send the walk to the line before", codes(more...))
		}
	})

	t.Run("a client that claims to be somebody else does not take that one's bucket", func(t *testing.T) {
		// The victim is a client of the proxy. An attacker that reaches the Gateway directly
		// and writes the victim's address in the header spends nothing of the victim's.
		gw, _ := addressGateway(t, 1000, 2, mustTrust(t, "10.0.0.0/8"))
		for i := 0; i < 5; i++ {
			loginFrom(gw, "203.0.113.50:4444", "198.51.100.4")
		}
		victim := loginFrom(gw, "10.0.0.2:5000", "198.51.100.4")
		if victim.Code != http.StatusOK {
			t.Fatalf("the victim's first attempt: %d, want 200: the attacker's requests were charged to the attacker", victim.Code)
		}
	})
}

func TestClientAddress_AuthenticatedTrafficIsPerClientToo(t *testing.T) {
	gw, _ := addressGateway(t, 1, 1000, mustTrust(t, "10.0.0.0/8"))
	a1 := getFrom(gw, "tok-alice", "10.0.0.2:5000", "203.0.113.9")
	a2 := getFrom(gw, "tok-alice", "10.0.0.2:5000", "203.0.113.9")
	// Somebody else, through the same proxy, with another token: not charged to the first.
	b1 := getFrom(gw, "tok-bob", "10.0.0.2:5000", "198.51.100.4")
	if a1.Code == http.StatusTooManyRequests || a2.Code != http.StatusTooManyRequests || b1.Code == http.StatusTooManyRequests {
		t.Fatalf("%s: want the first client's second request refused, and the second client untouched", codes(a1, a2, b1))
	}
	if got := a2.Header().Get("Retry-After"); got != "60" {
		t.Fatalf("Retry-After = %q, want 60", got)
	}
	// An address is charged before the token is looked at: a request without one is a request.
	req := httptest.NewRequest(http.MethodGet, "/sessions/s-1", nil)
	req.RemoteAddr = "10.0.0.2:5000"
	req.Header.Set("X-Forwarded-For", "192.0.2.77")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, req)
	req = httptest.NewRequest(http.MethodGet, "/sessions/s-1", nil)
	req.RemoteAddr = "10.0.0.2:5000"
	req.Header.Set("X-Forwarded-For", "192.0.2.77")
	rec2 := httptest.NewRecorder()
	gw.ServeHTTP(rec2, req)
	if rec.Code != http.StatusUnauthorized || rec2.Code != http.StatusTooManyRequests {
		t.Fatalf("two requests with no token from one client gave %d then %d, want 401 then 429", rec.Code, rec2.Code)
	}
}

// ADR-0014's budget is the user's, and stays the user's: the address is not what it is
// charged to, whatever the header says, and the budget of one user is not spent by another.
func TestClientAddress_TheSessionBudgetIsStillThePerUserOne(t *testing.T) {
	clock := &rateClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
	broker := newEverythingBroker(t)
	g := newTestGateway(t, twoUsers(t).URL, broker.srv.URL).
		WithSessionRequestLimiter(application.NewSessionRequestLimiter(2, 6).WithClock(clock.Now)).
		WithProxyTrust(mustTrust(t, "10.0.0.0/8")).Routes()

	post := func(token, xff string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/sessions", strings.NewReader(validSessionBody))
		req.Header.Set("Authorization", "Bearer "+token)
		req.RemoteAddr = "10.0.0.2:5000"
		req.Header.Set("X-Forwarded-For", xff)
		rec := httptest.NewRecorder()
		g.ServeHTTP(rec, req)
		return rec
	}
	// One user, from three different addresses: one budget.
	a1, a2, a3 := post("tok-alice", "203.0.113.1"), post("tok-alice", "203.0.113.2"), post("tok-alice", "203.0.113.3")
	// Another user, from the address the first one used: not charged to the first.
	b1 := post("tok-bob", "203.0.113.1")
	if codes(a1, a2, a3, b1) != "[200 200 429 200]" {
		t.Fatalf("%s: want the user's budget followed from address to address, and another user untouched", codes(a1, a2, a3, b1))
	}
}

func TestClientAddress_ADefaultGatewayTrustsNobody_AndNilKeepsWhatWasDeclared(t *testing.T) {
	build := func(t *testing.T) *interfaces.GatewayServer {
		clock := &rateClock{t: time.Date(2026, 10, 24, 9, 0, 0, 0, time.UTC)}
		auth := twoUsers(t)
		broker := newEverythingBroker(t)
		return interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL},
			application.NewRateLimiter(1000, time.Minute).WithClock(clock.Now),
			application.NewRateLimiter(2, time.Minute).WithClock(clock.Now),
			auth.URL, broker.srv.URL, "", "", "")
	}
	threeClients := func(h http.Handler) string {
		return codes(
			loginFrom(h, "10.0.0.2:5000", "203.0.113.1"),
			loginFrom(h, "10.0.0.2:5000", "203.0.113.2"),
			loginFrom(h, "10.0.0.2:5000", "203.0.113.3"))
	}
	t.Run("built by hand", func(t *testing.T) {
		// The peer is the client, and its three attempts share a bucket: its header is not read.
		if got := threeClients(build(t).Routes()); got != "[200 200 429]" {
			t.Fatalf("%s, want [200 200 429]", got)
		}
	})
	t.Run("WithProxyTrust(nil) keeps the default", func(t *testing.T) {
		if got := threeClients(build(t).WithProxyTrust(nil).Routes()); got != "[200 200 429]" {
			t.Fatalf("%s, want [200 200 429]", got)
		}
	})
	t.Run("WithProxyTrust(nil) does not forget a declaration", func(t *testing.T) {
		g := build(t).WithProxyTrust(mustTrust(t, "10.0.0.0/8")).WithProxyTrust(nil)
		if got := threeClients(g.Routes()); got != "[200 200 200]" {
			t.Fatalf("%s, want [200 200 200]: three clients behind a declared proxy", got)
		}
	})
}

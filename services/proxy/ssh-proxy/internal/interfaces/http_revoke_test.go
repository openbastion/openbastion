package interfaces_test

// The proxy's side of ending a session (ADR-0018): what revoke-session cuts, what it
// refuses to say, what it asks before it answers 200, and that a session it was told to
// cut gets no new ticket — including from a connect that was already in flight.

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

func revoke(srv *interfaces.HTTPServer, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/revoke-session", strings.NewReader(body)))
	return rec
}

func revokeResult(t *testing.T, rec *httptest.ResponseRecorder) (tickets, cut int) {
	t.Helper()
	var out struct {
		TicketsRevoked int `json:"tickets_revoked"`
		ConnectionsCut int `json:"connections_cut"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatalf("the answer is not the JSON the Broker reads: %q", rec.Body.String())
	}
	return out.TicketsRevoked, out.ConnectionsCut
}

func establishFor(srv *interfaces.HTTPServer, session string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	body := `{"session_id":"` + session + `","target_host":"10.0.0.5:22","target_user":"root","protocol":"ssh","vault_scope_token":"scope","ttl_seconds":60}`
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	return rec
}

func TestRevokeSession_CutsTheOpenConnections_DropsTheTickets_AndSaysHowMany(t *testing.T) {
	pending := infrastructure.NewPendingSessions()
	srv := newServer(pending)
	srv.Admit = func(context.Context, string, bool) error { return nil }
	t1, t2 := establishFor(srv, "A"), establishFor(srv, "A")
	other := establishFor(srv, "B")
	if t1.Code != 200 || t2.Code != 200 || other.Code != 200 {
		t.Fatalf("establish: %d %d %d", t1.Code, t2.Code, other.Code)
	}
	// Two connections of A are open; one of B.
	ctxA, cancelA := context.WithCancelCause(context.Background())
	defer cancelA(nil)
	ctxB, cancelB := context.WithCancelCause(context.Background())
	defer cancelB(nil)
	a1, _ := srv.Live.Begin("A", cancelA)
	a2, _ := srv.Live.Begin("A", cancelA)
	a3, _ := srv.Live.Begin("A", cancelA)
	_, _ = srv.Live.Begin("B", cancelB)
	go func() { // the relays end as soon as they are told to
		<-ctxA.Done()
		a1.RelayEnded()
		a2.RelayEnded()
		a3.RelayEnded()
	}()

	rec := revoke(srv, `{"session_id":"A","ttl_seconds":600}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d %q", rec.Code, rec.Body.String())
	}
	// Two tickets, three connections: the two numbers are told apart.
	if tickets, cut := revokeResult(t, rec); tickets != 2 || cut != 3 {
		t.Fatalf("tickets revoked %d, connections cut %d, want 2 and 3", tickets, cut)
	}
	if ctxA.Err() == nil {
		t.Fatal("the connection of A was not cut")
	}
	if ctxB.Err() != nil {
		t.Fatal("the connection of another session was cut")
	}
	// The ticket of B still works; the tickets of A do not.
	var tk struct {
		ConnectionTicket string `json:"connection_ticket"`
	}
	_ = json.Unmarshal(other.Body.Bytes(), &tk)
	if _, err := pending.Consume(tk.ConnectionTicket); err != nil {
		t.Fatalf("the ticket of an unrelated session was taken: %v", err)
	}
}

func TestRevokeSession_IsIdempotent_AndASessionItKnowsNothingOfIsA200(t *testing.T) {
	srv := newServer(infrastructure.NewPendingSessions())
	for i := 0; i < 2; i++ {
		rec := revoke(srv, `{"session_id":"nothing-here","ttl_seconds":60}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("call %d: %d %q, want 200", i+1, rec.Code, rec.Body.String())
		}
		if tickets, cut := revokeResult(t, rec); tickets != 0 || cut != 0 {
			t.Fatalf("call %d cut %d and revoked %d for a session with nothing", i+1, cut, tickets)
		}
	}
}

func TestRevokeSession_AnswersNo_IfAConnectionIsStillClosingWhenItGivesUp(t *testing.T) {
	srv := newServer(infrastructure.NewPendingSessions())
	srv.RevokeWait = 30 * time.Millisecond
	_, cancel := context.WithCancelCause(context.Background())
	conn, _ := srv.Live.Begin("A", cancel) // a relay that never ends

	rec := revoke(srv, `{"session_id":"A","ttl_seconds":60}`)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("a connection that did not stop: %d %q, want 503 — the Broker must not call the session ended", rec.Code, rec.Body.String())
	}
	if !srv.Live.Revoked("A") {
		t.Fatal("the revocation was not remembered: a retry would have nothing to build on, and a new connection would be accepted")
	}
	// Once it has stopped, the same call is a 200.
	conn.RelayEnded()
	if rec := revoke(srv, `{"session_id":"A","ttl_seconds":60}`); rec.Code != http.StatusOK {
		t.Fatalf("the same call once the connection stopped: %d %q, want 200", rec.Code, rec.Body.String())
	}
}

func TestRevokeSession_RefusesWhatIsNotAskedProperly_AndOnlyAPost(t *testing.T) {
	srv := newServer(infrastructure.NewPendingSessions())
	for name, body := range map[string]string{
		"no body":               ``,
		"not JSON":              `session_id=A`,
		"no session":            `{"ttl_seconds":60}`,
		"an empty session":      `{"session_id":"","ttl_seconds":60}`,
		"no time to remember":   `{"session_id":"A"}`,
		"a time of zero":        `{"session_id":"A","ttl_seconds":0}`,
		"a negative time":       `{"session_id":"A","ttl_seconds":-5}`,
		"a time that is text":   `{"session_id":"A","ttl_seconds":"60"}`,
		"a body past the bound": `{"session_id":"` + strings.Repeat("x", 1<<17) + `","ttl_seconds":60}`,
	} {
		if rec := revoke(srv, body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: %d %q, want 400", name, rec.Code, rec.Body.String())
		}
	}
	if srv.Live.Revoked("A") {
		t.Fatal("a refused request left a revocation behind")
	}
	for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodDelete} {
		rec := httptest.NewRecorder()
		srv.Routes().ServeHTTP(rec, httptest.NewRequest(method, "/internal/v1/revoke-session", strings.NewReader(`{"session_id":"A","ttl_seconds":60}`)))
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: %d, want 405", method, rec.Code)
		}
	}
	if srv.Live.Revoked("A") {
		t.Fatal("a refused method left a revocation behind")
	}
}

// A very large number of seconds must not wrap a Duration round into the past: a revocation
// that is forgotten at once is no revocation.
func TestRevokeSession_AHugeTimeIsCapped_NotWrappedIntoThePast(t *testing.T) {
	srv := newServer(infrastructure.NewPendingSessions())
	for _, secs := range []string{"9223372036", "1099511627776", "9223372036854775807"} {
		rec := revoke(srv, `{"session_id":"S`+secs+`","ttl_seconds":`+secs+`}`)
		if rec.Code != http.StatusOK {
			t.Fatalf("%s seconds: %d %q, want 200", secs, rec.Code, rec.Body.String())
		}
		if !srv.Live.Revoked("S" + secs) {
			t.Fatalf("a revocation of %s seconds is not remembered: the number wrapped", secs)
		}
	}
}

// The revocation is remembered for the time asked — the time the session had left — and for
// no more than the cap, however much is asked.
func TestRevokeSession_IsRememberedForTheTimeAsked_NeverMoreThanTheCap(t *testing.T) {
	for _, c := range []struct {
		name string
		body string
		want time.Duration
	}{
		{"a minute", `{"session_id":"S","ttl_seconds":60}`, time.Minute},
		{"an hour", `{"session_id":"S","ttl_seconds":3600}`, time.Hour},
		{"more than the cap", `{"session_id":"S","ttl_seconds":9223372036854775807}`, interfaces.MaxRevocationMemory},
	} {
		t.Run(c.name, func(t *testing.T) {
			srv := newServer(infrastructure.NewPendingSessions())
			before := time.Now()
			if rec := revoke(srv, c.body); rec.Code != http.StatusOK {
				t.Fatalf("%d %q", rec.Code, rec.Body.String())
			}
			until, ok := srv.Live.RevokedUntil("S")
			if !ok {
				t.Fatal("the revocation is not remembered")
			}
			if got := until.Sub(before); got < c.want-time.Second || got > c.want+5*time.Second {
				t.Fatalf("remembered for %v, want %v", got, c.want)
			}
		})
	}
}

func TestRevokeSession_WithoutARegistryTheProxyAnswers503_AndEstablishesNothing(t *testing.T) {
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "127.0.0.1:2222") // as built by hand: no registry
	srv.Admit = func(context.Context, string, bool) error { return nil }
	if rec := revoke(srv, `{"session_id":"A","ttl_seconds":60}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("revoke with no registry: %d, want 503: a revocation nobody could carry out is not a 200", rec.Code)
	}
	rec := establishFor(srv, "A")
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("establish with no registry: %d %q, want 503 and no ticket: a session that could not be cut is not started", rec.Code, rec.Body.String())
	}
}

func TestEstablishSession_ASessionTheProxyWasToldToCutGetsNoTicket(t *testing.T) {
	pending := infrastructure.NewPendingSessions()
	srv := newServer(pending)
	asked := 0
	srv.Admit = func(context.Context, string, bool) error { asked++; return nil }
	revoke(srv, `{"session_id":"A","ttl_seconds":60}`)

	rec := establishFor(srv, "A")
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("establish on a revoked session: %d %q, want 409 and no ticket", rec.Code, rec.Body.String())
	}
	if asked != 0 {
		t.Fatalf("the recorder was asked %d time(s) about a session that was ended: it is refused before anything else is done", asked)
	}
	if rec := establishFor(srv, "B"); rec.Code != http.StatusOK {
		t.Fatalf("establish on another session: %d, want 200 — the memory is per session", rec.Code)
	}
}

// The connect that was in flight: the first look at the registry says "not revoked", and the
// revocation lands before the ticket is registered. The ticket must not survive it.
func TestEstablishSession_ARevocationThatLandsDuringTheEstablishLeavesNoTicketBehind(t *testing.T) {
	pending := infrastructure.NewPendingSessions()
	srv := newServer(pending)
	srv.Admit = func(context.Context, string, bool) error { // runs between the first look and the registration
		srv.Live.Revoke("A", time.Now().Add(time.Hour))
		return nil
	}
	rec := establishFor(srv, "A")
	if rec.Code != http.StatusConflict || strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("%d %q, want 409 and no ticket", rec.Code, rec.Body.String())
	}
	if n := pending.RevokeSession("A"); n != 0 {
		t.Fatalf("%d ticket(s) of the revoked session were left registered", n)
	}
}

var _ = proxycore.ErrSessionRevoked

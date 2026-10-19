package interfaces_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/infrastructure"
	"github.com/openbastion/openbastion/services/proxy/ssh-proxy/internal/interfaces"
)

func establish(srv *interfaces.HTTPServer) *httptest.ResponseRecorder {
	return establishWith(srv, "")
}

// establishWith adds extra JSON members (each preceded by a comma) to the request.
func establishWith(srv *interfaces.HTTPServer, extra string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	body := `{"session_id":"s1","target_host":"10.0.0.5:22","target_user":"root","vault_scope_token":"scope","ttl_seconds":60` + extra + `}`
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	return rec
}

func TestEstablishSession_IssuesATicketWhenRecordingIsAdmitted(t *testing.T) {
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "127.0.0.1:2222")
	srv.Admit = func(context.Context, string, bool) error { return nil }
	if rec := establish(srv); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// Refused here, before a ticket exists: the operator learns at `connect`, not
// after opening a connection, and nothing is left registered for the session.
func TestEstablishSession_RefusesWithA503AndNoTicketWhenRecordingIsNotAdmitted(t *testing.T) {
	pending := infrastructure.NewPendingSessions()
	srv := interfaces.NewHTTPServer(pending, "127.0.0.1:2222")
	srv.Admit = func(context.Context, string, bool) error {
		return fmt.Errorf("%w: dial tcp 10.9.8.7:8087: connection refused", proxycore.ErrRecordingUnavailable)
	}

	rec := establish(srv)
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("got %d, want 503", rec.Code)
	}
	if !strings.HasPrefix(rec.Body.String(), "recording unavailable") {
		t.Fatalf("the Session Broker recognises the refusal by this prefix, got %q", rec.Body.String())
	}
	// The response travels back to the operator: the recorder's address stays in the log.
	if strings.Contains(rec.Body.String(), "10.9.8.7") {
		t.Fatalf("the refusal leaks the recorder's address: %q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("a refused session was handed a ticket: %q", rec.Body.String())
	}
	if _, err := pending.Consume("ticket_anything"); !errors.Is(err, infrastructure.ErrInvalidTicket) {
		t.Fatalf("unexpected pending state: %v", err)
	}
}

func TestEstablishSession_WithoutAnAdmitHookKeepsItsOldBehaviour(t *testing.T) {
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "127.0.0.1:2222")
	if rec := establish(srv); rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
}

// The Broker's break-glass authorisation (ADR-0009) is asked about at the door —
// so a waiver that this proxy would grant does not turn into a refusal — and
// travels with the ticket, so that the SSH side, where the session really
// starts, still knows it.
func TestEstablishSession_CarriesTheBreakGlassRequestToTheAdmissionAndTheTicket(t *testing.T) {
	for _, tc := range []struct {
		name  string
		extra string
		want  bool
	}{
		{"requested", `,"break_glass":true`, true},
		{"absent means no", ``, false},
		{"explicit no", `,"break_glass":false`, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pending := infrastructure.NewPendingSessions()
			srv := interfaces.NewHTTPServer(pending, "127.0.0.1:2222")
			var asked []bool
			srv.Admit = func(_ context.Context, _ string, breakGlass bool) error {
				asked = append(asked, breakGlass)
				return nil
			}
			rec := establishWith(srv, tc.extra)
			if rec.Code != http.StatusOK {
				t.Fatalf("got %d %q", rec.Code, rec.Body.String())
			}
			if len(asked) != 1 || asked[0] != tc.want {
				t.Fatalf("admission was asked with break-glass=%v, want [%v]", asked, tc.want)
			}
			var resp struct {
				ConnectionTicket string `json:"connection_ticket"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			ps, err := pending.Consume(resp.ConnectionTicket)
			if err != nil {
				t.Fatal(err)
			}
			if ps.BreakGlass != tc.want {
				t.Fatalf("the pending session carries break-glass=%v, want %v", ps.BreakGlass, tc.want)
			}
		})
	}
}

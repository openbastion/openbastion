package interfaces_test

import (
	"context"
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
	rec := httptest.NewRecorder()
	body := `{"session_id":"s1","target_host":"10.0.0.5:22","target_user":"root","vault_scope_token":"scope","ttl_seconds":60}`
	srv.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	return rec
}

func TestEstablishSession_IssuesATicketWhenRecordingIsAdmitted(t *testing.T) {
	srv := interfaces.NewHTTPServer(infrastructure.NewPendingSessions(), "127.0.0.1:2222")
	srv.Admit = func(context.Context, string) error { return nil }
	if rec := establish(srv); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "ticket_") {
		t.Fatalf("got %d %q", rec.Code, rec.Body.String())
	}
}

// Refused here, before a ticket exists: the operator learns at `connect`, not
// after opening a connection, and nothing is left registered for the session.
func TestEstablishSession_RefusesWithA503AndNoTicketWhenRecordingIsNotAdmitted(t *testing.T) {
	pending := infrastructure.NewPendingSessions()
	srv := interfaces.NewHTTPServer(pending, "127.0.0.1:2222")
	srv.Admit = func(context.Context, string) error {
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

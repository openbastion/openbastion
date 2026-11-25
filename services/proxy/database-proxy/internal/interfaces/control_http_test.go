package interfaces

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/mtls/mtlstest"
	"github.com/openbastion/openbastion/pkg/proxycore"
	"github.com/openbastion/openbastion/services/proxy/database-proxy/internal/domain"
)

func testControlServer(t *testing.T, admit func(context.Context, string, bool) error) (*HTTPServer, *domain.TicketStore, *proxycore.LiveSessions) {
	t.Helper()
	pending, err := domain.NewTicketStore(8, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	live := proxycore.NewLiveSessions()
	return NewHTTPServer(pending, live, "db-proxy.example:15432", admit), pending, live
}

func TestEstablishSessionReturnsOpaqueTicketWithoutScope(t *testing.T) {
	s, _, _ := testControlServer(t, func(context.Context, string, bool) error { return nil })
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"vault-scope-secret","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
	var out establishSessionResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ProxyEndpoint != "db-proxy.example:15432" || out.ConnectionTicket == "" {
		t.Fatalf("response = %#v", out)
	}
	if strings.Contains(rec.Body.String(), "vault-scope-secret") {
		t.Fatal("Vault scope token leaked in establish response")
	}
}

func TestEstablishSessionFailsClosedWhenRecordingAdmissionUnavailable(t *testing.T) {
	s, _, _ := testControlServer(t, func(context.Context, string, bool) error { return proxycore.ErrRecordingUnavailable })
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEstablishSessionRefusesTicketForRevokedSession(t *testing.T) {
	s, pending, live := testControlServer(t, func(context.Context, string, bool) error { return nil })
	live.Revoke("s1", time.Now().Add(time.Hour))
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if rec.Code != http.StatusConflict || pending.PendingCount() != 0 {
		t.Fatalf("status=%d pending=%d body=%s", rec.Code, pending.PendingCount(), rec.Body.String())
	}
}

func TestRevokeSessionRemovesPendingTicketAndCutsLiveConnection(t *testing.T) {
	s, pending, live := testControlServer(t, func(context.Context, string, bool) error { return nil })
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":300}`
	establish := httptest.NewRecorder()
	s.Routes().ServeHTTP(establish, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if establish.Code != http.StatusOK {
		t.Fatal(establish.Body.String())
	}
	ctx, cancel := context.WithCancelCause(context.Background())
	defer cancel(nil)
	conn, err := live.Begin("s1", cancel)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		<-ctx.Done()
		conn.RelayEnded()
	}()

	revokeBody := `{"session_id":"s1","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/revoke-session", strings.NewReader(revokeBody)))
	if rec.Code != http.StatusOK || !live.Revoked("s1") || pending.PendingCount() != 0 {
		t.Fatalf("status=%d revoked=%v pending=%d body=%s", rec.Code, live.Revoked("s1"), pending.PendingCount(), rec.Body.String())
	}
	conn.End()
}

func TestEstablishSessionRejectsUnknownFieldsAndWrongMethod(t *testing.T) {
	s, _, _ := testControlServer(t, func(context.Context, string, bool) error { return nil })
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":300,"target_password":"never"}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("unknown field status=%d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/establish-session", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("wrong method status=%d", rec.Code)
	}
}

func TestEstablishSessionRefusesInvalidTTL(t *testing.T) {
	s, _, _ := testControlServer(t, func(context.Context, string, bool) error { return nil })
	for _, ttl := range []string{"0", "-1", "999999"} {
		body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":` + ttl + `}`
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
		if rec.Code != http.StatusBadRequest {
			t.Errorf("ttl %s status=%d body=%s", ttl, rec.Code, rec.Body.String())
		}
	}
}

func TestRevokeSessionFailsClosedWhenConnectionsDoNotClose(t *testing.T) {
	s, _, live := testControlServer(t, func(context.Context, string, bool) error { return nil })
	_, cancel := context.WithCancelCause(context.Background())
	conn, err := live.Begin("s1", cancel)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.End()
	s.RevokeWait = time.Millisecond
	body := `{"session_id":"s1","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/revoke-session", strings.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestEstablishSessionDoesNotReturnInternalErrorDetails(t *testing.T) {
	s, _, _ := testControlServer(t, func(context.Context, string, bool) error {
		return errors.New("recorder at 10.0.0.1:8087 refused secret material")
	})
	body := `{"session_id":"s1","actor_id":"alice","target_host":"db.internal:5432","target_user":"app","vault_scope_token":"scope","ttl_seconds":300}`
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/internal/v1/establish-session", strings.NewReader(body)))
	if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "10.0.0.1") || strings.Contains(rec.Body.String(), "secret material") {
		t.Fatalf("status=%d body=%s", rec.Code, rec.Body.String())
	}
}

func TestCallerRulesOnlyAllowSessionBrokerToControlSessions(t *testing.T) {
	mtlstest.Check(t, CallerRules(), []mtlstest.Case{
		mtlstest.Allow("session-broker", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("command-recorder", "POST", "/internal/v1/establish-session"),
		mtlstest.Deny("session-broker", "GET", "/internal/v1/establish-session"),
		mtlstest.Allow("session-broker", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("api-gateway", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("password-vault", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("database-proxy", "POST", "/internal/v1/revoke-session"),
		mtlstest.Deny("session-broker", "DELETE", "/internal/v1/revoke-session"),
		mtlstest.Allow("api-gateway", "GET", "/healthz"),
	})
}

func TestEveryControlRouteHasAnExplicitCallerRule(t *testing.T) {
	mtlstest.CheckRoutes(t, NewHTTPServer(nil, nil, "", nil).Routes(), CallerRules(), []mtlstest.Route{
		{Method: http.MethodPost, Path: "/internal/v1/establish-session"},
		{Method: http.MethodPost, Path: "/internal/v1/revoke-session"},
		{Method: http.MethodGet, Path: "/healthz"},
	})
}

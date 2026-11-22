package interfaces_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

func TestSecretInjectionReconciliation_GatewayRequiresExplicitAuthorizationAndUsesVerifiedRoles(t *testing.T) {
	auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"audit-reader"})
	defer auth.Close()
	var authzBody map[string]any
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/authz/v1/capabilities" || r.Method != http.MethodPost {
			t.Errorf("Authorization request %s %s", r.Method, r.URL.Path)
		}
		_ = json.NewDecoder(r.Body).Decode(&authzBody)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"allowed":[true]}`))
	}))
	defer authz.Close()
	var auditCalls int
	const cursor = "0123456789abcdef0123456789abcdef"
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auditCalls++
		if r.URL.Path != "/audit/v1/secret-injections" || r.URL.Query().Get("limit") != "500" || r.URL.Query().Get("before") != cursor {
			t.Errorf("Audit request: %s", r.URL.String())
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"outcomes":[],"coverage":"retained_audit_chain","archived_history_excluded":false,"has_more":false}`))
	}))
	defer audit.Close()
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", authz.URL, "").WithAuditServiceURL(audit.URL)
	req := httptest.NewRequest(http.MethodGet, "/audit/secret-injections?limit=500&before="+cursor, nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response %d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
	}
	queries, _ := authzBody["queries"].([]any)
	query, _ := func() (map[string]any, bool) {
		if len(queries) != 1 {
			return nil, false
		}
		q, ok := queries[0].(map[string]any)
		return q, ok
	}()
	if query["resource"] != "audit:secret-injections:all" || query["action"] != "audit:secret-injections:read" || query["prefix"] == true {
		t.Fatalf("wrong policy request: %#v", authzBody)
	}
	roles, _ := authzBody["actor_roles"].([]any)
	if len(roles) != 1 || roles[0] != "audit-reader" {
		t.Fatalf("roles not taken from verified token: %#v", authzBody)
	}
	if auditCalls != 1 {
		t.Fatalf("Audit calls = %d", auditCalls)
	}
}

func TestSecretInjectionReconciliation_DeniesWithoutPolicyAndDoesNotCallAudit(t *testing.T) {
	auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"platform-admin"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"allowed":[false]}`)) }))
	defer authz.Close()
	auditCalls := 0
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { auditCalls++ }))
	defer audit.Close()
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", authz.URL, "").WithAuditServiceURL(audit.URL)
	req := httptest.NewRequest(http.MethodGet, "/audit/secret-injections", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response %d %q", rec.Code, rec.Body.String())
	}
	if auditCalls != 0 {
		t.Fatalf("unauthorized request reached Audit %d times", auditCalls)
	}
}

func TestSecretInjectionReconciliation_RejectsForgedQueryAndAuthzFailureClosed(t *testing.T) {
	for _, tc := range []struct {
		name, query string
		authzStatus int
		want        int
	}{
		{"forged actor", "?actorRoles=platform-admin", http.StatusOK, http.StatusBadRequest},
		{"authorization down", "", http.StatusServiceUnavailable, http.StatusServiceUnavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"user"})
			defer auth.Close()
			authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(tc.authzStatus) }))
			defer authz.Close()
			gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", authz.URL, "").WithAuditServiceURL("http://127.0.0.1:1")
			req := httptest.NewRequest(http.MethodGet, "/audit/secret-injections"+tc.query, nil)
			req.Header.Set("Authorization", "Bearer good-token")
			rec := httptest.NewRecorder()
			gw.Routes().ServeHTTP(rec, req)
			if rec.Code != tc.want {
				t.Fatalf("got %d want %d: %s", rec.Code, tc.want, strings.TrimSpace(rec.Body.String()))
			}
		})
	}
}

func TestSecretInjectionReconciliation_AuditFailureIsGenericAndNoStore(t *testing.T) {
	auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"audit-reader"})
	defer auth.Close()
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"allowed":[true]}`)) }))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "private archive path /srv/audit/archive", http.StatusServiceUnavailable)
	}))
	defer audit.Close()
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", authz.URL, "").WithAuditServiceURL(audit.URL)
	req := httptest.NewRequest(http.MethodGet, "/audit/secret-injections", nil)
	req.Header.Set("Authorization", "Bearer good-token")
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response %d headers=%v", rec.Code, rec.Header())
	}
	if strings.Contains(rec.Body.String(), "/srv/audit/archive") {
		t.Fatalf("internal Audit diagnostic leaked: %q", rec.Body.String())
	}
}

func TestSecretInjectionReconciliation_RejectsOutOfRangeLimitAndNonCanonicalCursorBeforeAuthorization(t *testing.T) {
	auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"audit-reader"})
	defer auth.Close()
	authzCalls, auditCalls := 0, 0
	authz := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authzCalls++
		_, _ = w.Write([]byte(`{"allowed":[true]}`))
	}))
	defer authz.Close()
	audit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { auditCalls++ }))
	defer audit.Close()
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", authz.URL, "").WithAuditServiceURL(audit.URL)
	for _, path := range []string{
		"/audit/secret-injections?limit=501",
		"/audit/secret-injections?before=ABCDEF0123456789ABCDEF0123456789",
		"/audit/secret-injections?actorRoles=platform-admin",
	} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer good-token")
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusBadRequest || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("%s: status=%d headers=%v body=%q", path, rec.Code, rec.Header(), rec.Body.String())
		}
	}
	if authzCalls != 0 || auditCalls != 0 {
		t.Fatalf("invalid query reached downstream services: authz=%d audit=%d", authzCalls, auditCalls)
	}
}

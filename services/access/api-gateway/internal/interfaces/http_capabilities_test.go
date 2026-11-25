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

// ADR-0131: GET /auth/me/capabilities asks the Authorization Service, for the verified caller's
// roles only, the closed catalogue of Admin UI questions, and answers one boolean per name.

type capabilitiesAuthz struct {
	roles   []string
	queries []map[string]any
	answer  func(q map[string]any) bool
	status  int
	extra   int // answers more (or fewer) booleans than asked
}

func (c *capabilitiesAuthz) server(t *testing.T) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/authz/v1/capabilities" {
			t.Errorf("Authorization request %s %s", r.Method, r.URL.Path)
		}
		var body struct {
			ActorRoles []string         `json:"actor_roles"`
			Queries    []map[string]any `json:"queries"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.roles, c.queries = body.ActorRoles, body.Queries
		if c.status != 0 {
			w.WriteHeader(c.status)
			return
		}
		allowed := make([]bool, len(body.Queries)+c.extra)
		for i := range allowed {
			allowed[i] = i < len(body.Queries) && c.answer(body.Queries[i])
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"allowed": allowed})
	}))
}

func capabilitiesGateway(t *testing.T, authz *capabilitiesAuthz) (*interfaces.GatewayServer, func()) {
	auth := newFakeTokenVerifierServer(t, "good-token", "user-verified", "operator", []string{"ops"})
	az := authz.server(t)
	gw := interfaces.NewGatewayServer(&infrastructure.AuthenticationHTTPClient{BaseURL: auth.URL}, application.NewRateLimiter(100, time.Minute), application.NewRateLimiter(100, time.Minute), auth.URL, "", "", az.URL, "")
	return gw, func() { auth.Close(); az.Close() }
}

func getCapabilities(gw *interfaces.GatewayServer, method, target, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	return rec
}

func TestCapabilities_AsksForTheVerifiedRolesAndAnswersEachName(t *testing.T) {
	// The caller may rotate accounts and approve break-glass requests only.
	authz := &capabilitiesAuthz{answer: func(q map[string]any) bool {
		return q["action"] == "vault:account:rotate" && q["prefix"] == true ||
			q["resource"] == "breakglass-approve:account:" && q["action"] == "session:approve"
	}}
	gw, done := capabilitiesGateway(t, authz)
	defer done()
	rec := getCapabilities(gw, http.MethodGet, "/auth/me/capabilities", "good-token")
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("response %d %v %s", rec.Code, rec.Header(), rec.Body.String())
	}
	if len(authz.roles) != 1 || authz.roles[0] != "ops" {
		t.Fatalf("roles not the verified token's: %v", authz.roles)
	}
	var got struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"accounts.list": false, "accounts.onboard": false, "accounts.rotate": true, "accounts.disable": false,
		"accounts.pin": false, "accounts.approval": false, "accounts.screenProfile": false, "accounts.kerberos": false, "policies.create": false, "sessions.create": false,
		"sessions.breakglass": false, "sessions.approve": true, "sessions.read": false, "sessions.terminate": false,
		"secrets.inject": false, "secrets.paste": false, "recordings.read": false, "audit.secretInjections": false,
		"approvalHierarchy.read": false, "approvalHierarchy.manage": false, "approvalHierarchy.reports": false,
	}
	if len(got.Capabilities) != len(want) {
		t.Fatalf("capabilities %v, want the %d names of the catalogue", got.Capabilities, len(want))
	}
	for name, v := range want {
		if allowed, ok := got.Capabilities[name]; !ok || allowed != v {
			t.Fatalf("%s = %v (present %v), want %v; all: %v", name, allowed, ok, v, got.Capabilities)
		}
	}
	// The questions are the services' own resources and actions.
	asked := map[string]bool{}
	for _, q := range authz.queries {
		asked[q["resource"].(string)+" "+q["action"].(string)] = true
	}
	for _, q := range []string{"vault:account-admin:* vault:account:list", "authz:policy-admin authz:policy:create", "recording:session: recording:session:read", "audit:secret-injections:all audit:secret-injections:read", "approval-hierarchy:user: approval-hierarchy:read", "approval-hierarchy:all approval-hierarchy:read", "approval-hierarchy:user: approval-hierarchy:manage", "approval-hierarchy:all approval-hierarchy:manage", "approval-hierarchy:reports: approval-hierarchy:read", "approval-hierarchy:all approval-hierarchy:read"} {
		if !asked[q] {
			t.Fatalf("question %q not asked: %v", q, asked)
		}
	}
}

func TestCapabilities_GlobalHierarchyPermissionMakesHierarchyVisible(t *testing.T) {
	authz := &capabilitiesAuthz{answer: func(q map[string]any) bool {
		return q["resource"] == "approval-hierarchy:all" &&
			(q["action"] == "approval-hierarchy:read" || q["action"] == "approval-hierarchy:manage")
	}}
	gw, done := capabilitiesGateway(t, authz)
	defer done()
	rec := getCapabilities(gw, http.MethodGet, "/auth/me/capabilities", "good-token")
	if rec.Code != http.StatusOK {
		t.Fatalf("response %d %s", rec.Code, rec.Body.String())
	}
	var got struct {
		Capabilities map[string]bool `json:"capabilities"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"approvalHierarchy.read", "approvalHierarchy.manage", "approvalHierarchy.reports"} {
		if !got.Capabilities[name] {
			t.Fatalf("global hierarchy permission did not enable %s: %v", name, got.Capabilities)
		}
	}
}

func TestCapabilities_RefusesWithoutTokenAnyParameterAndAnyOtherMethod(t *testing.T) {
	authz := &capabilitiesAuthz{answer: func(map[string]any) bool { return true }}
	gw, done := capabilitiesGateway(t, authz)
	defer done()
	if rec := getCapabilities(gw, http.MethodGet, "/auth/me/capabilities", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token: %d", rec.Code)
	}
	if rec := getCapabilities(gw, http.MethodGet, "/auth/me/capabilities?roles=platform-admin", "good-token"); rec.Code != http.StatusBadRequest {
		t.Fatalf("a parameter: %d", rec.Code)
	}
	if rec := getCapabilities(gw, http.MethodPost, "/auth/me/capabilities", "good-token"); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("POST: %d", rec.Code)
	}
	if authz.queries != nil {
		t.Fatal("a refused request reached the Authorization Service")
	}
}

func TestCapabilities_AnAuthorizationFailureIs503AndSaysNothingOfIt(t *testing.T) {
	for name, authz := range map[string]*capabilitiesAuthz{
		"unavailable":       {status: http.StatusServiceUnavailable},
		"forbidden by mTLS": {status: http.StatusForbidden},
		"one answer more":   {answer: func(map[string]any) bool { return true }, extra: 1},
		"one answer less":   {answer: func(map[string]any) bool { return true }, extra: -1},
	} {
		t.Run(name, func(t *testing.T) {
			gw, done := capabilitiesGateway(t, authz)
			defer done()
			rec := getCapabilities(gw, http.MethodGet, "/auth/me/capabilities", "good-token")
			if rec.Code != http.StatusServiceUnavailable || strings.Contains(rec.Body.String(), "true") {
				t.Fatalf("%d %s", rec.Code, rec.Body.String())
			}
		})
	}
}

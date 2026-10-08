package interfaces_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/api-gateway/internal/application"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/api-gateway/internal/interfaces"
)

// newFakeTokenVerifierServer stands in for a real Authentication Service —
// used to control exactly what identity the Gateway resolves for a given
// token, independent of whatever a malicious client might claim in its
// own request body.
func newFakeTokenVerifierServer(t *testing.T, validToken, userID, username string, roles []string) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/auth/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		if req.Token != validToken {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"userId": userID, "username": username, "roles": roles,
		})
	})
	mux.HandleFunc("/auth/v1/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"accessToken": validToken, "expiresIn": 3600})
	})
	return httptest.NewServer(mux)
}

// capturingSessionBroker records the exact JSON body it received for
// POST /sessions, so tests can assert on what the Gateway actually
// forwarded — the whole point being to prove the client's own claims
// about requestedBy/actorRoles never survive.
type capturingSessionBroker struct {
	srv          *httptest.Server
	lastBody     map[string]any
	responseCode int
}

func newCapturingSessionBroker(t *testing.T) *capturingSessionBroker {
	t.Helper()
	c := &capturingSessionBroker{responseCode: http.StatusCreated}
	mux := http.NewServeMux()
	mux.HandleFunc("/sessions", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.lastBody = body
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(c.responseCode)
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "session-fake", "status": "active"})
	})
	mux.HandleFunc("/sessions/session-fake/connect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"proxyEndpoint": "127.0.0.1:2222", "ticket": "tix-fake"})
	})
	c.srv = httptest.NewServer(mux)
	return c
}

// capturingVault records what the Gateway forwards to Password Vault's
// internal endpoints, and what path GET requests hit.
type capturingVault struct {
	srv           *httptest.Server
	lastOnboard   map[string]any
	lastRotate    map[string]any
	lastGetPath   string
}

func newCapturingVault(t *testing.T) *capturingVault {
	t.Helper()
	c := &capturingVault{}
	mux := http.NewServeMux()
	mux.HandleFunc("/vault/v1/onboard-account", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.lastOnboard = body
		w.WriteHeader(http.StatusCreated)
	})
	mux.HandleFunc("/vault/v1/rotate", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.lastRotate = body
		w.WriteHeader(http.StatusAccepted)
	})
	mux.HandleFunc("/vault/v1/accounts/", func(w http.ResponseWriter, r *http.Request) {
		c.lastGetPath = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"id": "acc1", "name": "fake-account", "username": "root", "targetHost": "10.0.0.9:22"})
	})
	c.srv = httptest.NewServer(mux)
	return c
}

// capturingAuthorization records what the Gateway forwards to
// Authorization's policy-creation endpoint.
type capturingAuthorization struct {
	srv      *httptest.Server
	lastBody map[string]any
}

func newCapturingAuthorization(t *testing.T) *capturingAuthorization {
	t.Helper()
	c := &capturingAuthorization{}
	mux := http.NewServeMux()
	mux.HandleFunc("/authz/v1/policies", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		c.lastBody = body
		w.WriteHeader(http.StatusCreated)
	})
	c.srv = httptest.NewServer(mux)
	return c
}

func newTestGateway(t *testing.T, authURL, brokerURL string, extra ...string) *interfaces.GatewayServer {
	t.Helper()
	vaultURL, authorizationURL := "", ""
	if len(extra) > 0 {
		vaultURL = extra[0]
	}
	if len(extra) > 1 {
		authorizationURL = extra[1]
	}
	authClient := &infrastructure.AuthenticationHTTPClient{BaseURL: authURL}
	requestLimiter := application.NewRateLimiter(1000, time.Minute)
	loginLimiter := application.NewRateLimiter(1000, time.Minute)
	return interfaces.NewGatewayServer(authClient, requestLimiter, loginLimiter, authURL, brokerURL, vaultURL, authorizationURL)
}

func TestHandleSessionsCollection_InjectsVerifiedIdentityOverridingClientClaims(t *testing.T) {
	const validToken = "tok-real-user"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_real", "realuser", []string{"dba"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()

	gw := newTestGateway(t, authSrv.URL, broker.srv.URL)

	// The client claims to be someone else entirely, with admin rights.
	maliciousBody, _ := json.Marshal(map[string]any{
		"requestedBy":     "attacker-controlled-user-id",
		"actorRoles":      []string{"admin", "super-root"},
		"targetAccountId": "acc1",
		"protocol":        "ssh",
		"justification":   "totally legitimate",
		"durationMinutes": 60,
	})
	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader(maliciousBody))
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()

	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if broker.lastBody == nil {
		t.Fatal("Session Broker never received a request")
	}
	if broker.lastBody["requestedBy"] != "user_real" {
		t.Fatalf("expected requestedBy to be overridden to the verified identity 'user_real', got %v", broker.lastBody["requestedBy"])
	}
	roles, _ := broker.lastBody["actorRoles"].([]any)
	if len(roles) != 1 || roles[0] != "dba" {
		t.Fatalf("expected actorRoles to be overridden to the verified ['dba'], got %v — client-claimed admin role leaked through", roles)
	}
}

func TestRequireAuth_RejectsMissingBearerToken(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "irrelevant", "u1", "u1", nil)
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a bearer token, got %d", rec.Code)
	}
	if broker.lastBody != nil {
		t.Fatal("Session Broker should never have been called without a valid token")
	}
}

func TestRequireAuth_RejectsInvalidToken(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "the-real-token", "u1", "u1", nil)
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/sessions", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("Authorization", "Bearer some-forged-token")
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 for an invalid token, got %d", rec.Code)
	}
}

func TestHandleLogin_ForwardsToAuthenticationWithoutRequiringAuth(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "issued-token", "u1", "u1", nil)
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader([]byte(`{"username":"u1","password":"pw"}`)))
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.AccessToken != "issued-token" {
		t.Fatalf("expected the token issued by Authentication to be relayed, got %q", out.AccessToken)
	}
}

func TestHandleLogin_RateLimited(t *testing.T) {
	authSrv := newFakeTokenVerifierServer(t, "tok", "u1", "u1", nil)
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()

	authClient := &infrastructure.AuthenticationHTTPClient{BaseURL: authSrv.URL}
	requestLimiter := application.NewRateLimiter(1000, time.Minute)
	loginLimiter := application.NewRateLimiter(2, time.Minute) // deliberately tiny for this test
	gw := interfaces.NewGatewayServer(authClient, requestLimiter, loginLimiter, authSrv.URL, broker.srv.URL, "", "")

	body := []byte(`{"username":"u1","password":"pw"}`)
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: expected 200 within the limit, got %d", i+1, rec.Code)
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/auth/login", bytes.NewReader(body))
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("expected the 3rd login attempt to be rate limited (429), got %d", rec.Code)
	}
}

func TestHandleSessionItem_PassthroughForwardsToSessionBroker(t *testing.T) {
	const validToken = "tok-real-user"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_real", "realuser", []string{"dba"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL)

	req := httptest.NewRequest(http.MethodPost, "/sessions/session-fake/connect", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Ticket string `json:"ticket"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Ticket != "tix-fake" {
		t.Fatalf("expected the connection ticket to be relayed from Session Broker, got %q", out.Ticket)
	}
}

// -- admin surfaces: /vault/accounts/*, /policies --------------------------

func TestHandleVaultAccountsCollection_ForwardsOnboardingToVault(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"vault-admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	body, _ := json.Marshal(map[string]any{
		"id": "acc1", "name": "prod-db-01-root", "username": "root",
		"targetHost": "10.0.4.12:22", "protocol": "ssh", "rotationPolicy": "manual",
		"initialSecret": []byte("s3cret"), "actorRoles": []string{"attacker-claimed-role"},
	})
	req := httptest.NewRequest(http.MethodPost, "/vault/accounts", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastOnboard == nil || vault.lastOnboard["name"] != "prod-db-01-root" {
		t.Fatalf("expected the onboarding request to reach Vault, got %v", vault.lastOnboard)
	}
	roles, _ := vault.lastOnboard["actorRoles"].([]any)
	if len(roles) != 1 || roles[0] != "vault-admin" {
		t.Fatalf("expected actorRoles overridden to the verified ['vault-admin'], got %v", roles)
	}
}

func TestHandleVaultAccountItem_GetForwardsToVault(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/vault/accounts/acc1", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastGetPath != "/vault/v1/accounts/acc1" {
		t.Fatalf("expected Vault to receive /vault/v1/accounts/acc1, got %q", vault.lastGetPath)
	}
	var out struct {
		Username string `json:"username"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.Username != "root" {
		t.Fatalf("expected account metadata to be relayed, got %+v", out)
	}
}

func TestHandleVaultAccountItem_RotateTranslatesPathToBodyWithNoSecret(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	req := httptest.NewRequest(http.MethodPost, "/vault/accounts/acc1/rotate", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusAccepted {
		t.Fatalf("expected 202, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastRotate == nil || vault.lastRotate["accountId"] != "acc1" {
		t.Fatalf("expected Vault to receive accountId 'acc1' translated from the URL path, got %v", vault.lastRotate)
	}
	if _, hasSecret := vault.lastRotate["newSecret"]; hasSecret {
		t.Fatal("expected no client-supplied secret to be forwarded — rotation must be auto-generated by Vault")
	}
	roles, _ := vault.lastRotate["actorRoles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("expected the verified caller roles to be included so Vault can RBAC-gate the rotation, got %v", roles)
	}
}

func TestHandlePoliciesCollection_InjectsVerifiedUsernameAsCreatedByOverridingClientClaim(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "real-admin", []string{"admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	authz := newCapturingAuthorization(t)
	defer authz.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, "", authz.srv.URL)

	body, _ := json.Marshal(map[string]any{
		"name": "dba-prod-db", "role": "dba", "resourcePattern": "vault:account:prod-*",
		"effect": "allow", "createdBy": "someone-else-entirely",
		"actorRoles": []string{"super-admin-i-am-not"},
	})
	req := httptest.NewRequest(http.MethodPost, "/policies", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d: %s", rec.Code, rec.Body.String())
	}
	if authz.lastBody == nil {
		t.Fatal("Authorization never received a request")
	}
	roles, _ := authz.lastBody["actorRoles"].([]any)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("expected the verified caller roles ['admin'] to override the client's forged actorRoles claim, got %v", roles)
	}
	if authz.lastBody["createdBy"] != "real-admin" {
		t.Fatalf("expected createdBy to be overridden to the verified username 'real-admin', got %v", authz.lastBody["createdBy"])
	}
}

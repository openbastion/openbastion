package interfaces_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
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
// internal endpoints, and what path/query GET, DELETE, and list requests
// carry.
type capturingVault struct {
	srv             *httptest.Server
	lastOnboard     map[string]any
	lastRotate      map[string]any
	lastGetPath     string
	lastListQuery   url.Values
	lastDeletePath  string
	lastDeleteQuery url.Values
	lastPinPath     string
	lastPin         map[string]any
	pinCalls        int
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
	mux.HandleFunc("/vault/v1/accounts", func(w http.ResponseWriter, r *http.Request) {
		c.lastListQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"items": []map[string]any{{"id": "acc1", "name": "fake-account", "username": "root", "targetHost": "10.0.0.9:22"}},
			"page":  1, "pageSize": 20, "totalItems": 1,
		})
	})
	mux.HandleFunc("/vault/v1/accounts/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			c.pinCalls++
			c.lastPinPath = r.URL.Path
			_ = json.NewDecoder(r.Body).Decode(&c.lastPin)
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{"hostKeyFingerprint": "SHA256:fake"})
			return
		}
		if r.Method == http.MethodDelete {
			c.lastDeletePath = r.URL.Path
			c.lastDeleteQuery = r.URL.Query()
			w.WriteHeader(http.StatusNoContent)
			return
		}
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
	vaultURL, authorizationURL, commandRecorderURL := "", "", ""
	if len(extra) > 0 {
		vaultURL = extra[0]
	}
	if len(extra) > 1 {
		authorizationURL = extra[1]
	}
	if len(extra) > 2 {
		commandRecorderURL = extra[2]
	}
	authClient := &infrastructure.AuthenticationHTTPClient{BaseURL: authURL}
	requestLimiter := application.NewRateLimiter(1000, time.Minute)
	loginLimiter := application.NewRateLimiter(1000, time.Minute)
	return interfaces.NewGatewayServer(authClient, requestLimiter, loginLimiter, authURL, brokerURL, vaultURL, authorizationURL, commandRecorderURL)
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
	gw := interfaces.NewGatewayServer(authClient, requestLimiter, loginLimiter, authSrv.URL, broker.srv.URL, "", "", "")

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

// PUT /vault/accounts/{id}/host-key (ADR-0039): the key is the client's, who pins it is the
// verified token's. Attack: a client that names another actor and grants itself a role in the
// body. Counter-proof: the key it sent is forwarded as it is.
func TestHandleVaultAccountItem_PinHostKeyTakesOnlyTheKeyFromTheClient(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"operator"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	body := `{"hostKey":"ssh-ed25519 AAAAkey","actorId":"user_root","actorRoles":["vault-admin"]}`
	req := httptest.NewRequest(http.MethodPut, "/vault/accounts/acc1/host-key", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastPinPath != "/vault/v1/accounts/acc1/host-key" {
		t.Fatalf("forwarded to %q", vault.lastPinPath)
	}
	if vault.lastPin["hostKey"] != "ssh-ed25519 AAAAkey" {
		t.Fatalf("the key was not forwarded as sent: %v", vault.lastPin)
	}
	if vault.lastPin["actorId"] != "user_admin" {
		t.Fatalf("the actor is the client's claim, not the token's: %v", vault.lastPin["actorId"])
	}
	roles, _ := vault.lastPin["actorRoles"].([]any)
	if len(roles) != 1 || roles[0] != "operator" {
		t.Fatalf("the roles are the client's claim, not the token's: %v", roles)
	}

	for _, path := range []string{"/vault/accounts//host-key", "/vault/accounts/a/b/host-key"} {
		vault.lastPinPath = ""
		req := httptest.NewRequest(http.MethodPut, path, strings.NewReader(`{"hostKey":"k"}`))
		req.Header.Set("Authorization", "Bearer "+validToken)
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		if vault.lastPinPath != "" {
			t.Fatalf("%s was forwarded to %s", path, vault.lastPinPath)
		}
	}
}

// PUT /vault/accounts/{id}/approval (ADR-0067): the setting is the client's, who sets it is
// the verified token's. Attack: a body that names another actor, grants itself a role and
// slips a host key in. Counter-proof: the setting is forwarded; without it, nothing is.
func TestHandleVaultAccountItem_SetApprovalTakesOnlyTheSettingFromTheClient(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"operator"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/vault/accounts/acc1/approval", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+validToken)
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		return rec
	}

	if rec := put(`{"actorId":"user_root"}`); rec.Code != http.StatusBadRequest || vault.lastPinPath != "" {
		t.Fatalf("without the setting: %d, forwarded to %q", rec.Code, vault.lastPinPath)
	}
	rec := put(`{"approvalRequired":true,"actorId":"user_root","actorRoles":["vault-admin"],"hostKey":"ssh-ed25519 AAAAevil"}`)
	if rec.Code != http.StatusOK || vault.lastPinPath != "/vault/v1/accounts/acc1/approval" {
		t.Fatalf("%d, forwarded to %q", rec.Code, vault.lastPinPath)
	}
	roles, _ := vault.lastPin["actorRoles"].([]any)
	if vault.lastPin["approvalRequired"] != true || vault.lastPin["actorId"] != "user_admin" || len(roles) != 1 || roles[0] != "operator" {
		t.Fatalf("forwarded %v", vault.lastPin)
	}
	if _, slipped := vault.lastPin["hostKey"]; slipped {
		t.Fatalf("a host key rode along: %v", vault.lastPin)
	}
}

func TestHandleVaultAccountItem_ApprovalChangesAreRateLimitedPerVerifiedUser(t *testing.T) {
	authMux := http.NewServeMux()
	authMux.HandleFunc("/auth/v1/verify", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Token string `json:"token"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		user := map[string]string{"alice-token": "alice", "bob-token": "bob"}[req.Token]
		if user == "" {
			http.Error(w, "invalid token", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"userId": user, "username": user, "roles": []string{"vault-admin"}})
	})
	authSrv := httptest.NewServer(authMux)
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "").
		WithVaultAccountActionLimiter(application.NewVaultAccountActionLimiter(1, 6))
	put := func(token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/vault/accounts/acc1/approval", strings.NewReader(`{"approvalRequired":true}`))
		req.Header.Set("Authorization", "Bearer "+token)
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		return rec
	}

	if rec := put("alice-token"); rec.Code != http.StatusOK {
		t.Fatalf("Alice's first change: %d %q", rec.Code, rec.Body.String())
	}
	if rec := put("alice-token"); rec.Code != http.StatusTooManyRequests || rec.Header().Get("Retry-After") != "10" {
		t.Fatalf("Alice's second change: %d %q, Retry-After=%q", rec.Code, rec.Body.String(), rec.Header().Get("Retry-After"))
	}
	if vault.pinCalls != 1 {
		t.Fatalf("%d approval changes reached the Vault after Alice's refusal, want 1", vault.pinCalls)
	}
	if rec := put("bob-token"); rec.Code != http.StatusOK {
		t.Fatalf("Bob has an independent budget: %d %q", rec.Code, rec.Body.String())
	}
	if vault.pinCalls != 2 {
		t.Fatalf("%d approval changes reached the Vault, want 2", vault.pinCalls)
	}
}

func TestHandleVaultAccountsCollection_GetListForwardsPageParamsAndInjectsActorRoles(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"vault-admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	req := httptest.NewRequest(http.MethodGet, "/vault/accounts?page=2&pageSize=10", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastListQuery == nil {
		t.Fatal("Vault never received the list request")
	}
	if vault.lastListQuery.Get("page") != "2" || vault.lastListQuery.Get("pageSize") != "10" {
		t.Fatalf("expected page/pageSize to pass through unchanged, got %v", vault.lastListQuery)
	}
	if vault.lastListQuery.Get("actorRoles") != "vault-admin" {
		t.Fatalf("expected the verified caller roles injected as actorRoles, got %q", vault.lastListQuery.Get("actorRoles"))
	}
	var out struct {
		TotalItems int `json:"totalItems"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if out.TotalItems != 1 {
		t.Fatalf("expected the paged response to be relayed, got %+v", out)
	}
}

func TestHandleVaultAccountItem_DeleteForwardsToVaultWithActorRolesInQuery(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"vault-admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	req := httptest.NewRequest(http.MethodDelete, "/vault/accounts/acc1", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d: %s", rec.Code, rec.Body.String())
	}
	if vault.lastDeletePath != "/vault/v1/accounts/acc1" {
		t.Fatalf("expected Vault to receive DELETE /vault/v1/accounts/acc1, got %q", vault.lastDeletePath)
	}
	if vault.lastDeleteQuery.Get("actorRoles") != "vault-admin" {
		t.Fatalf("expected the verified caller roles injected as actorRoles, got %q", vault.lastDeleteQuery.Get("actorRoles"))
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

// -- GET /sessions/{id}/recording -------------------------------------------

// capturingRecorder stands in for the Command Recorder and records what the
// Gateway forwards to it.
type capturingRecorder struct {
	srv       *httptest.Server
	lastPath  string
	lastQuery url.Values
	calls     int
}

func newCapturingRecorder(t *testing.T) *capturingRecorder {
	t.Helper()
	c := &capturingRecorder{}
	c.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.calls++
		c.lastPath = r.URL.EscapedPath()
		c.lastQuery = r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sessionId": "sess-1", "entries": []any{}, "page": 1, "pageSize": 20, "totalEntries": 0})
	}))
	return c
}

func TestHandleSessionRecording_RoutesToTheCommandRecorderWithTheVerifiedUserAndRolesOnly(t *testing.T) {
	const validToken = "tok-auditor"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_aud", "auditor1", []string{"auditor", "reader"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	recorder := newCapturingRecorder(t)
	defer recorder.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, "", "", recorder.srv.URL)

	// The client tries to smuggle its own callerId, actorRoles and an unrelated parameter.
	req := httptest.NewRequest(http.MethodGet, "/sessions/sess-1/recording?page=2&pageSize=50&callerId=user_victim&actorRoles=platform-admin&evil=1", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if recorder.lastPath != "/recorder/v1/sessions/sess-1/commands" {
		t.Fatalf("routed to %q", recorder.lastPath)
	}
	// The Recorder writes the read to the audit under this name (ADR-0022): it is the token's.
	if got := recorder.lastQuery["callerId"]; len(got) != 1 || got[0] != "user_aud" {
		t.Fatalf("callerId must be the verified user's, got %q — a client-supplied value leaked through", got)
	}
	if got := recorder.lastQuery.Get("actorRoles"); got != "auditor,reader" {
		t.Fatalf("actorRoles must be the verified ones, got %q — a client-supplied value leaked through", got)
	}
	if recorder.lastQuery.Get("page") != "2" || recorder.lastQuery.Get("pageSize") != "50" {
		t.Fatalf("page/pageSize were not forwarded: %v", recorder.lastQuery)
	}
	if recorder.lastQuery.Has("evil") {
		t.Fatalf("an arbitrary client parameter reached the Command Recorder: %v", recorder.lastQuery)
	}
	if broker.lastBody != nil {
		t.Fatal("the recording route must not reach the Session Broker")
	}
}

func TestHandleSessionRecording_EscapesTheSessionIDInThePath(t *testing.T) {
	const validToken = "tok-auditor"
	authSrv := newFakeTokenVerifierServer(t, validToken, "u", "u", []string{"auditor"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	recorder := newCapturingRecorder(t)
	defer recorder.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, "", "", recorder.srv.URL)

	req := httptest.NewRequest(http.MethodGet, "/sessions/a%3Fb%23c/recording", nil)
	req.Header.Set("Authorization", "Bearer "+validToken)
	rec := httptest.NewRecorder()
	gw.Routes().ServeHTTP(rec, req)

	if recorder.lastPath != "/recorder/v1/sessions/a%3Fb%23c/commands" || recorder.lastQuery.Has("c") {
		t.Fatalf("a session id with ? and # must stay inside the path, got path=%q query=%v", recorder.lastPath, recorder.lastQuery)
	}
}

func TestHandleSessionRecording_OnlyGetAndRequiresAToken(t *testing.T) {
	const validToken = "tok-auditor"
	authSrv := newFakeTokenVerifierServer(t, validToken, "u", "u", []string{"auditor"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	recorder := newCapturingRecorder(t)
	defer recorder.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, "", "", recorder.srv.URL)

	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodDelete} {
		req := httptest.NewRequest(method, "/sessions/sess-1/recording", nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		if rec.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s: expected 405, got %d", method, rec.Code)
		}
	}

	noToken := httptest.NewRecorder()
	gw.Routes().ServeHTTP(noToken, httptest.NewRequest(http.MethodGet, "/sessions/sess-1/recording", nil))
	if noToken.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 without a token, got %d", noToken.Code)
	}
	if recorder.calls != 0 {
		t.Fatalf("no refused request may reach the Command Recorder, got %d call(s)", recorder.calls)
	}
}

// ADR-0043: a path that cannot become an internal request (a control character) is a generic
// 500 — the error of building it names the internal URL, which the client must never read.
func TestGateway_ARequestItCannotBuild_NamesNoInternalURL(t *testing.T) {
	const validToken = "tok-admin"
	authSrv := newFakeTokenVerifierServer(t, validToken, "user_admin", "admin1", []string{"vault-admin"})
	defer authSrv.Close()
	broker := newCapturingSessionBroker(t)
	defer broker.srv.Close()
	vault := newCapturingVault(t)
	defer vault.srv.Close()
	gw := newTestGateway(t, authSrv.URL, broker.srv.URL, vault.srv.URL, "")

	for _, path := range []string{"/vault/accounts/acc%0a1", "/vault/accounts/acc%7f"} {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+validToken)
		rec := httptest.NewRecorder()
		gw.Routes().ServeHTTP(rec, req)
		host := strings.TrimPrefix(vault.srv.URL, "http://")
		if strings.Contains(rec.Body.String(), host) || strings.Contains(rec.Body.String(), "/vault/v1/") {
			t.Fatalf("%s: the internal URL reached the client: %d %q", path, rec.Code, rec.Body.String())
		}
		if rec.Code != http.StatusInternalServerError && rec.Code != http.StatusBadRequest && rec.Code != http.StatusNotFound {
			t.Fatalf("%s: %d", path, rec.Code)
		}
	}
}

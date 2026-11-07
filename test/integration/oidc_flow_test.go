package integration_test

// Federated login with OpenID Connect (ADR-0035) on a real Gateway and a real Authentication
// Service against a real PostgreSQL, with a provider played by this test. Before ADR-0035
// there was no federated login at all: this is written first and seen to fail.

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// testIdP is an OpenID Connect provider: discovery, keys, an authorize endpoint that sends the
// browser back with a code at once, and a token endpoint that checks PKCE and the client.
type testIdP struct {
	srv    *httptest.Server
	key    *rsa.PrivateKey
	mu     sync.Mutex
	groups map[string][]string // subject -> groups, what the next login of that subject says
	next   string              // the subject the next authorize logs in
	codes  map[string]idpCode
}

type idpCode struct {
	challenge, nonce, subject, redirect string
}

func startTestIdP(t *testing.T, clientID, secret string) *testIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	idp := &testIdP{key: key, groups: map[string][]string{}, codes: map[string]idpCode{}}
	mux := http.NewServeMux()
	idp.srv = httptest.NewServer(mux)
	t.Cleanup(idp.srv.Close)
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": idp.srv.URL, "authorization_endpoint": idp.srv.URL + "/authorize",
			"token_endpoint": idp.srv.URL + "/token", "jwks_uri": idp.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		enc := base64.RawURLEncoding.EncodeToString
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
			"n": enc(key.PublicKey.N.Bytes()), "e": enc(big.NewInt(int64(key.PublicKey.E)).Bytes())}}})
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != clientID || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" {
			http.Error(w, "bad request", http.StatusBadRequest)
			return
		}
		idp.mu.Lock()
		code := fmt.Sprintf("code-%d", len(idp.codes)+1)
		idp.codes[code] = idpCode{challenge: q.Get("code_challenge"), nonce: q.Get("nonce"), subject: idp.next, redirect: q.Get("redirect_uri")}
		idp.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?"+url.Values{"code": {code}, "state": {q.Get("state")}}.Encode(), http.StatusFound)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		user, pass, _ := r.BasicAuth()
		idp.mu.Lock()
		c, ok := idp.codes[r.PostForm.Get("code")]
		delete(idp.codes, r.PostForm.Get("code"))
		groups := idp.groups[c.subject]
		idp.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if !ok || user != clientID || pass != secret || c.challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || r.PostForm.Get("redirect_uri") != c.redirect {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		now := time.Now()
		_ = json.NewEncoder(w).Encode(map[string]string{"token_type": "Bearer", "id_token": idp.sign(map[string]any{
			"iss": idp.srv.URL, "aud": clientID, "sub": c.subject, "nonce": c.nonce, "iat": now.Unix(),
			"exp": now.Add(5 * time.Minute).Unix(), "name": c.subject + " (display)", "groups": groups})})
	})
	return idp
}

func (idp *testIdP) sign(claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	p, _ := json.Marshal(claims)
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, idp.key, crypto.SHA256, sum[:])
	return signing + "." + enc(sig)
}

func (idp *testIdP) as(subject string, groups ...string) {
	idp.mu.Lock()
	defer idp.mu.Unlock()
	idp.next, idp.groups[subject] = subject, groups
}

// federatedLogin plays the browser: start at the Gateway, go to the provider, come back with
// the code and the state to the Gateway.
func federatedLogin(t *testing.T, gatewayURL string) (status int, body string, code, state string) {
	t.Helper()
	resp, err := http.Post(gatewayURL+"/auth/oidc/start", "application/json", nil)
	if err != nil {
		t.Fatal(err)
	}
	var started struct {
		AuthorizationURL string `json:"authorizationUrl"`
	}
	raw, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || json.Unmarshal(raw, &started) != nil || started.AuthorizationURL == "" {
		t.Fatalf("start: %d %s", resp.StatusCode, raw)
	}
	noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	resp, err = noFollow.Get(started.AuthorizationURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	back, err := url.Parse(resp.Header.Get("Location"))
	if err != nil || resp.StatusCode != http.StatusFound {
		t.Fatalf("authorize: %d %q", resp.StatusCode, resp.Header.Get("Location"))
	}
	code, state = back.Query().Get("code"), back.Query().Get("state")
	status, body = oidcCallback(t, gatewayURL, code, state)
	return status, body, code, state
}

func oidcCallback(t *testing.T, gatewayURL, code, state string) (int, string) {
	t.Helper()
	b, _ := json.Marshal(map[string]string{"code": code, "state": state})
	resp, err := http.Post(gatewayURL+"/auth/oidc/callback", "application/json", bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

// tokenClaims reads the claims of an OpenBastion token (its signature is the Gateway's business).
func tokenClaims(t *testing.T, body string) (username string, roles []string) {
	t.Helper()
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	if err := json.Unmarshal([]byte(body), &tok); err != nil {
		t.Fatalf("not a token: %s", body)
	}
	p, err := base64.RawURLEncoding.DecodeString(strings.Split(tok.AccessToken, ".")[1])
	if err != nil {
		t.Fatal(err)
	}
	var c struct {
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
	}
	_ = json.Unmarshal(p, &c)
	return c.Username, c.Roles
}

func TestPostgresFlow_FederatedLoginWithOIDC_RolesFromTheDeclaredMapOnly(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// The provider of the variables is bound to the issuer of an earlier run's IdP (ADR-0078).
	forgetIssuerBindings(t, db, "")
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-35")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-35")
	const clientID, secret = "openbastion-it", "client-secret-it-0123456789"
	idp := startTestIdP(t, clientID, secret)
	roleMap := filepath.Join(t.TempDir(), "roles.json")
	if err := os.WriteFile(roleMap, []byte(`{"bastion-admins": ["platform-admin", "vault-admin"], "dbas": ["dba"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	signing := testKMSKeyHex(t)
	oidcEnv := []string{"OIDC_ISSUER=" + idp.srv.URL, "OIDC_CLIENT_ID=" + clientID, "OIDC_CLIENT_SECRET=" + secret,
		"OIDC_REDIRECT_URL=http://127.0.0.1:5173/oidc/callback", "OIDC_ROLE_MAP_FILE=" + roleMap}
	authnEnv := append([]string{"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + signing, "SKIP_DEMO_SEED=1"}, oidcEnv...)

	t.Run("OIDC is all or nothing, its provider must be found and its map must be right", func(t *testing.T) {
		bad := filepath.Join(t.TempDir(), "bad.json")
		_ = os.WriteFile(bad, []byte(`{"admins": ["Platform Admin"]}`), 0o600)
		for name, env := range map[string][]string{
			"half configured":      {"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + signing, "OIDC_ISSUER=" + idp.srv.URL},
			"a role map not right": append(append([]string{}, authnEnv[:3]...), "OIDC_ISSUER="+idp.srv.URL, "OIDC_CLIENT_ID="+clientID, "OIDC_CLIENT_SECRET="+secret, "OIDC_REDIRECT_URL=http://127.0.0.1:5173/cb", "OIDC_ROLE_MAP_FILE="+bad),
			"no provider there":    append(append([]string{}, authnEnv[:3]...), "OIDC_ISSUER=http://127.0.0.1:1", "OIDC_CLIENT_ID="+clientID, "OIDC_CLIENT_SECRET="+secret, "OIDC_REDIRECT_URL=http://127.0.0.1:5173/cb", "OIDC_ROLE_MAP_FILE="+roleMap),
			"an issuer over http":  append(append([]string{}, authnEnv[:3]...), "OIDC_ISSUER=http://idp.example", "OIDC_CLIENT_ID="+clientID, "OIDC_CLIENT_SECRET="+secret, "OIDC_REDIRECT_URL=http://127.0.0.1:5173/cb", "OIDC_ROLE_MAP_FILE="+roleMap),
		} {
			out := runUntilExit(t, root, authnBin, append([]string{"PORT=19493"}, env...)...)
			if !strings.Contains(out, "OIDC") {
				t.Fatalf("%s: expected a refusal naming OIDC, got:\n%s", name, out)
			}
			if strings.Contains(out, secret) {
				t.Fatalf("%s: the client secret is in the output", name)
			}
		}
	})

	authn := startService(t, root, authnBin, "19491", authnEnv...)
	// A federated login takes twice from the per-address login budget (start, then callback):
	// this test logs in often, from one address.
	gateway := startService(t, root, gatewayBin, "19492", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	if !strings.Contains(authn.out.String(), "federated login (OIDC) with "+idp.srv.URL) {
		t.Fatalf("the start does not say federated login is on:\n%s", authn.out.String())
	}

	t.Run("the federated routes take from the per-address login budget", func(t *testing.T) {
		tight := startService(t, root, gatewayBin, "19494", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=2")
		codes := []int{}
		for i := 0; i < 3; i++ {
			resp, err := http.Post(tight.baseURL+"/auth/oidc/start", "application/json", nil)
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			codes = append(codes, resp.StatusCode)
		}
		if fmt.Sprint(codes) != "[200 200 429]" {
			t.Fatalf("three starts with a budget of two: %v", codes)
		}
		if status, _ := oidcCallback(t, tight.baseURL, "c", "s"); status != http.StatusTooManyRequests {
			t.Fatalf("a callback past the budget: %d, want 429", status)
		}
	})

	var adminSub = fmt.Sprintf("sub-admin-%d", time.Now().UnixNano())
	t.Run("a federated login gets the roles the map gives its groups, and nothing else", func(t *testing.T) {
		idp.as(adminSub, "bastion-admins", "platform-admin", "marketing")
		status, body, _, _ := federatedLogin(t, gateway.baseURL)
		if status != http.StatusOK {
			t.Fatalf("callback: %d %s", status, body)
		}
		username, roles := tokenClaims(t, body)
		if username != "oidc:"+adminSub || fmt.Sprint(roles) != "[platform-admin vault-admin]" {
			t.Fatalf("token for %q with %v, want oidc:%s with [platform-admin vault-admin]", username, roles, adminSub)
		}
		var source, subject string
		if err := db.QueryRow(`SELECT identity_source, external_subject FROM users WHERE username = $1`, "oidc:"+adminSub).Scan(&source, &subject); err != nil || source != "oidc" || subject != adminSub {
			t.Fatalf("stored account: %q %q %v", source, subject, err)
		}
	})

	t.Run("a callback replayed is refused", func(t *testing.T) {
		idp.as(adminSub, "dbas")
		status, _, code, state := federatedLogin(t, gateway.baseURL)
		if status != http.StatusOK {
			t.Fatalf("first: %d", status)
		}
		if status, body := oidcCallback(t, gateway.baseURL, code, state); status != http.StatusUnauthorized {
			t.Fatalf("the same code and state again: %d %s, want 401", status, body)
		}
		if status, _ := oidcCallback(t, gateway.baseURL, "code-forged", "state-forged"); status != http.StatusUnauthorized {
			t.Fatalf("a forged state: %d, want 401", status)
		}
	})

	t.Run("the roles follow the groups: leaving one at the provider removes its role at the next login", func(t *testing.T) {
		idp.as(adminSub, "dbas")
		_, body, _, _ := federatedLogin(t, gateway.baseURL)
		if _, roles := tokenClaims(t, body); fmt.Sprint(roles) != "[dba]" {
			t.Fatalf("roles %v, want [dba]", roles)
		}
		var stored string
		_ = db.QueryRow(`SELECT array_to_string(roles, ',') FROM users WHERE username = $1`, "oidc:"+adminSub).Scan(&stored)
		if stored != "dba" {
			t.Fatalf("roles stored for the account: %q, want dba — the account says what its last login gave", stored)
		}
	})

	t.Run("an identity no group of the map covers is refused, and no account is made", func(t *testing.T) {
		outsider := fmt.Sprintf("sub-outsider-%d", time.Now().UnixNano())
		idp.as(outsider, "marketing")
		if status, body, _, _ := federatedLogin(t, gateway.baseURL); status != http.StatusForbidden || strings.Contains(body, "marketing") {
			t.Fatalf("callback: %d %s, want 403 without the groups", status, body)
		}
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM users WHERE external_subject = $1`, outsider).Scan(&n)
		if n != 0 {
			t.Fatal("an account was made for an identity with no role")
		}
	})

	t.Run("a federated account has no password here", func(t *testing.T) {
		for _, pw := range []string{"", "anything"} {
			if _, status := gatewayLogin(t, gateway.baseURL, "oidc:"+adminSub, pw); status != http.StatusUnauthorized {
				t.Fatalf("local login of the federated account with %q: %d, want 401", pw, status)
			}
		}
	})

	t.Run("a login started before a restart of the Authentication Service ends after it", func(t *testing.T) {
		idp.as(adminSub, "bastion-admins")
		resp, err := http.Post(gateway.baseURL+"/auth/oidc/start", "application/json", nil)
		if err != nil {
			t.Fatal(err)
		}
		var started struct {
			AuthorizationURL string `json:"authorizationUrl"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&started)
		resp.Body.Close()
		stopService(t, authn)
		again := startService(t, root, authnBin, "19491", authnEnv...)
		noFollow := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
		resp, err = noFollow.Get(started.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		back, _ := url.Parse(resp.Header.Get("Location"))
		if status, body := oidcCallback(t, gateway.baseURL, back.Query().Get("code"), back.Query().Get("state")); status != http.StatusOK {
			t.Fatalf("callback after the restart: %d %s — the attempt must be in the database, not in a process", status, body)
		}
		if strings.Contains(again.out.String()+authn.out.String(), secret) {
			t.Fatal("the client secret is in the Authentication Service's log")
		}
	})
}

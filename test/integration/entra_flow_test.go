package integration_test

// ADR-0079 on real processes, under PostgreSQL, without a Microsoft tenant: the Authentication
// Service reaches "login.microsoftonline.com" — a fake Entra ID served over TLS by this test, with
// a certificate of a test authority the service is told to trust (SSL_CERT_FILE), through a test
// CONNECT proxy (HTTPS_PROXY). Nothing in the service is changed for the test: the issuer is the
// real one, https, exactly. The proxy says every host the service asked for: no Graph.

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
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

const entraHost = "login.microsoftonline.com"

// fakeEntra serves the v2 endpoints of several tenants, under their own paths.
type fakeEntra struct {
	srv      *httptest.Server
	key      *rsa.PrivateKey
	clientID string
	secret   string
	mu       sync.Mutex
	next     map[string]any            // claims added to the next token (tid, groups, overage, …)
	drop     []string                  // claims removed from the next token
	codes    map[string]map[string]any // code -> claims
	verifier map[string]string         // code -> PKCE challenge
}

func startFakeEntra(t *testing.T, clientID, secret string, cert tls.Certificate) *fakeEntra {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeEntra{key: key, clientID: clientID, secret: secret, codes: map[string]map[string]any{}, verifier: map[string]string{}}
	base := "https://" + entraHost
	f.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		parts := strings.SplitN(strings.TrimPrefix(r.URL.Path, "/"), "/", 2) // <tenant>/<rest>
		if len(parts) != 2 {
			http.NotFound(w, r)
			return
		}
		tenant, rest := parts[0], parts[1]
		issuer := base + "/" + tenant + "/v2.0"
		switch rest {
		case "v2.0/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer,
				"authorization_endpoint": base + "/" + tenant + "/oauth2/v2.0/authorize",
				"token_endpoint":         base + "/" + tenant + "/oauth2/v2.0/token",
				"jwks_uri":               base + "/" + tenant + "/discovery/v2.0/keys"})
		case "discovery/v2.0/keys":
			enc := base64.RawURLEncoding.EncodeToString
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "RSA", "kid": "k1", "use": "sig",
				"n": enc(f.key.N.Bytes()), "e": enc(big.NewInt(int64(f.key.E)).Bytes())}}})
		case "oauth2/v2.0/authorize":
			q := r.URL.Query()
			code := fmt.Sprintf("code-%d", time.Now().UnixNano())
			f.mu.Lock()
			claims := map[string]any{"iss": issuer, "aud": q.Get("client_id"), "nonce": q.Get("nonce"), "tid": tenant,
				"iat": time.Now().Unix(), "exp": time.Now().Add(5 * time.Minute).Unix(), "name": "Entra user"}
			for k, v := range f.next {
				claims[k] = v
			}
			for _, k := range f.drop {
				delete(claims, k)
			}
			f.codes[code], f.verifier[code] = claims, q.Get("code_challenge")
			f.mu.Unlock()
			back, _ := url.Parse(q.Get("redirect_uri"))
			bq := back.Query()
			bq.Set("code", code)
			bq.Set("state", q.Get("state"))
			back.RawQuery = bq.Encode()
			http.Redirect(w, r, back.String(), http.StatusFound)
		case "oauth2/v2.0/token":
			_ = r.ParseForm()
			user, pass, _ := r.BasicAuth()
			code := r.PostForm.Get("code")
			sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
			f.mu.Lock()
			claims, challenge := f.codes[code], f.verifier[code]
			delete(f.codes, code)
			f.mu.Unlock()
			if claims == nil || challenge != base64.RawURLEncoding.EncodeToString(sum[:]) || user != f.clientID || pass != f.secret {
				http.Error(w, "invalid_grant", http.StatusBadRequest)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.sign(t, claims), "token_type": "Bearer"})
		default:
			http.NotFound(w, r)
		}
	}))
	f.srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
	f.srv.StartTLS()
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeEntra) sign(t *testing.T, claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	h, _ := json.Marshal(map[string]string{"alg": "RS256", "typ": "JWT", "kid": "k1"})
	p, _ := json.Marshal(claims)
	signing := enc(h) + "." + enc(p)
	sum := sha256.Sum256([]byte(signing))
	sig, err := rsa.SignPKCS1v15(rand.Reader, f.key, crypto.SHA256, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	return signing + "." + enc(sig)
}

// as sets what the next login's token says, on top of a valid token of its tenant.
func (f *fakeEntra) as(claims map[string]any, drop ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.next, f.drop = claims, drop
}

// connectProxy is an HTTPS proxy that sends every CONNECT to target and remembers the hosts asked.
type connectProxy struct {
	url    string
	mu     sync.Mutex
	hosts  []string
	target string
}

func startConnectProxy(t *testing.T, target string) *connectProxy {
	t.Helper()
	p := &connectProxy{target: target}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p.url = "http://" + ln.Addr().String()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(c)
		}
	}()
	return p
}

func (p *connectProxy) serve(c net.Conn) {
	defer c.Close()
	req, err := http.ReadRequest(bufio.NewReader(c))
	if err != nil || req.Method != http.MethodConnect {
		return
	}
	p.mu.Lock()
	p.hosts = append(p.hosts, req.Host)
	p.mu.Unlock()
	if !strings.HasPrefix(req.Host, entraHost+":") {
		_, _ = io.WriteString(c, "HTTP/1.1 403 Forbidden\r\n\r\n")
		return
	}
	up, err := net.Dial("tcp", p.target)
	if err != nil {
		return
	}
	defer up.Close()
	_, _ = io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
	done := make(chan struct{}, 2)
	go func() { _, _ = io.Copy(up, c); done <- struct{}{} }()
	go func() { _, _ = io.Copy(c, up); done <- struct{}{} }()
	<-done
}

func (p *connectProxy) asked() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.hosts...)
}

// testAuthority makes a CA and a certificate for login.microsoftonline.com; the CA's PEM file.
func testAuthority(t *testing.T, dir string) (tls.Certificate, string, *x509.CertPool) {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OpenBastion test authority (ADR-0079)"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)
	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: entraHost}, DNSNames: []string{entraHost},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caFile := filepath.Join(dir, "test-ca.pem")
	if err := os.WriteFile(caFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}), 0o644); err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey}, caFile, pool
}

func TestEntra_TwoTenants_OneTenantPerProvider_GroupsOnlyFromItsMap_OverageRefused(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-79")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-79")
	conf := t.TempDir()
	cert, caFile, pool := testAuthority(t, conf)
	const clientID, secret = "openbastion-entra", "entra-client-secret-0123456789"
	entra := startFakeEntra(t, clientID, secret, cert)
	proxy := startConnectProxy(t, strings.TrimPrefix(entra.srv.URL, "https://"))
	run := fmt.Sprint(time.Now().UnixNano())
	tenantA := "a" + run[len(run)-7:] + "-1111-4111-8111-111111111111"
	tenantB := "b" + run[len(run)-7:] + "-2222-4222-8222-222222222222"
	idA, idB := "entra-a-"+run, "entra-b-"+run
	forgetIssuerBindings(t, db, idA, idB)

	secretFile := writeFile(t, conf, "client-secret", secret, 0o600)
	roles := writeFile(t, conf, "roles.json", `{"g-dbas": ["dba"]}`, 0o600)
	entry := func(id, tenant, issuer string) string {
		return fmt.Sprintf(`{"id": %q, "label": %q, "profile": "entra", "tenant_id": %q, "issuer": %q, "client_id": %q, "client_secret_file": %q, "redirect_url": "http://127.0.0.1:5173/oidc/callback", "role_map_file": %q}`,
			id, id, tenant, issuer, clientID, secretFile, roles)
	}
	issuerOf := func(tenant string) string { return "https://" + entraHost + "/" + tenant + "/v2.0" }
	providers := func(name string, entries ...string) string {
		return writeFile(t, conf, name, `{"oidc": [`+strings.Join(entries, ", ")+`]}`, 0o644)
	}
	env := func(file string) []string {
		return []string{"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + testKMSKeyHex(t), "SKIP_DEMO_SEED=1",
			"IDENTITY_PROVIDERS_FILE=" + file, "HTTPS_PROXY=" + proxy.url, "SSL_CERT_FILE=" + caFile}
	}

	t.Run("a multi-tenant authority, or an issuer of another tenant, refuses the start", func(t *testing.T) {
		for name, e := range map[string]string{
			"common":                entry("x-"+run, "common", issuerOf("common")),
			"another tenant issuer": entry("x-"+run, tenantA, issuerOf(tenantB)),
		} {
			out := runUntilExit(t, root, authnBin, append(env(providers("bad.json", e)), "PORT=19851")...)
			if !strings.Contains(out, "refusing to start") || !strings.Contains(out, "Entra ID") || strings.Contains(out, secret) {
				t.Fatalf("%s:\n%s", name, out)
			}
		}
	})

	file := providers("providers.json", entry(idA, tenantA, issuerOf(tenantA)), entry(idB, tenantB, issuerOf(tenantB)))
	authn := startService(t, root, authnBin, "19852", env(file)...)
	gateway := startService(t, root, gatewayBin, "19853", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	if out := authn.out.String(); !strings.Contains(out, "Entra ID, tenant "+tenantA) || !strings.Contains(out, "Entra ID, tenant "+tenantB) {
		t.Fatalf("the start does not say the two Entra ID providers:\n%s", out)
	}
	browser := &http.Client{
		Transport:     &http.Transport{Proxy: func(*http.Request) (*url.URL, error) { return url.Parse(proxy.url) }, TLSClientConfig: &tls.Config{RootCAs: pool}},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	login := func(provider string) (int, string) {
		t.Helper()
		resp, err := http.Post(gateway.baseURL+"/auth/oidc/start", "application/json", strings.NewReader(fmt.Sprintf(`{"provider": %q}`, provider)))
		if err != nil {
			t.Fatal(err)
		}
		raw, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		var started struct {
			AuthorizationURL string `json:"authorizationUrl"`
		}
		if json.Unmarshal(raw, &started) != nil || !strings.HasPrefix(started.AuthorizationURL, "https://"+entraHost+"/") {
			t.Fatalf("start at %s: %d %s", provider, resp.StatusCode, raw)
		}
		if strings.Contains(started.AuthorizationURL, "groups") {
			t.Fatalf("the authorization asks a groups scope of Entra ID: %s", started.AuthorizationURL)
		}
		resp, err = browser.Get(started.AuthorizationURL)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		back, _ := url.Parse(resp.Header.Get("Location"))
		return oidcCallback(t, gateway.baseURL, back.Query().Get("code"), back.Query().Get("state"))
	}
	accounts := func(sub string) int {
		var n int
		_ = db.QueryRow(`SELECT count(*) FROM users WHERE identity_source = 'oidc' AND external_subject = $1`, sub).Scan(&n)
		return n
	}
	sub := "sub-" + run

	t.Run("the same sub at two tenants is two accounts, each with the roles of its own map", func(t *testing.T) {
		entra.as(map[string]any{"sub": sub, "groups": []string{"g-dbas"}})
		status, body := login(idA)
		if status != http.StatusOK {
			t.Fatalf("login at %s: %d %s", idA, status, body)
		}
		nameA, rolesA := tokenClaims(t, body)
		status, body = login(idB)
		if status != http.StatusOK {
			t.Fatalf("login at %s: %d %s", idB, status, body)
		}
		nameB, _ := tokenClaims(t, body)
		if nameA != "oidc:"+idA+":"+sub || nameB != "oidc:"+idB+":"+sub || fmt.Sprint(rolesA) != "[dba]" {
			t.Fatalf("accounts %s and %s with %v, want two accounts with [dba]", nameA, nameB, rolesA)
		}
	})

	refused := func(t *testing.T, what string, claims map[string]any, want int, drop ...string) {
		t.Helper()
		s := "sub-refused-" + fmt.Sprint(time.Now().UnixNano())
		claims["sub"] = s
		entra.as(claims, drop...)
		if status, body := login(idA); status != want || strings.Contains(body, "accessToken") {
			t.Fatalf("%s: %d %s, want %d and no token", what, status, body, want)
		}
		if n := accounts(s); n != 0 {
			t.Fatalf("%s: %d account(s) made", what, n)
		}
	}
	t.Run("a token of another tenant, or without one, is refused: no account, no token", func(t *testing.T) {
		refused(t, "another tenant", map[string]any{"tid": tenantB, "groups": []string{"g-dbas"}}, http.StatusUnauthorized)
		refused(t, "no tid", map[string]any{"groups": []string{"g-dbas"}}, http.StatusUnauthorized, "tid")
	})

	t.Run("roles come from the map only: a roles claim or an unknown group gives nothing", func(t *testing.T) {
		refused(t, "a roles claim", map[string]any{"roles": []string{"platform-admin"}, "groups": []string{"g-unknown"}}, http.StatusForbidden)
		refused(t, "no groups", map[string]any{"roles": []string{"platform-admin"}}, http.StatusForbidden, "groups")
	})

	t.Run("a groups overage is refused, and its reference is never fetched", func(t *testing.T) {
		graph := "https://graph.microsoft.com/v1.0/users/" + sub + "/getMemberObjects"
		refused(t, "_claim_sources", map[string]any{"_claim_names": map[string]string{"groups": "src1"},
			"_claim_sources": map[string]any{"src1": map[string]string{"endpoint": graph}}}, http.StatusUnauthorized, "groups")
		refused(t, "hasgroups", map[string]any{"hasgroups": true}, http.StatusUnauthorized, "groups")
		if len(proxy.asked()) == 0 {
			t.Fatal("the proxy saw nothing: the service did not reach the fake Entra ID through it")
		}
		for _, h := range proxy.asked() {
			if !strings.HasPrefix(h, entraHost+":") {
				t.Fatalf("the service asked the proxy for %s: only %s may be reached", h, entraHost)
			}
		}
	})

	t.Run("another tenant under the same id refuses the start (ADR-0078)", func(t *testing.T) {
		stopService(t, gateway)
		stopService(t, authn)
		tenantC := "c" + run[len(run)-7:] + "-3333-4333-8333-333333333333"
		out := runUntilExit(t, root, authnBin, append(env(providers("moved.json", entry(idA, tenantC, issuerOf(tenantC)))), "PORT=19854")...)
		if !strings.Contains(out, fmt.Sprintf("oidc %q is bound to the issuer %s", idA, issuerOf(tenantA))) {
			t.Fatalf("a new tenant under %s:\n%s", idA, out)
		}
	})
}

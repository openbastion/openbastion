package infrastructure_test

// The OpenID Connect client (ADR-0035) against a provider played by this test: every check of
// the ID token, and the attacks each one is there for.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

type fakeIdP struct {
	srv    *httptest.Server
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	weak   *rsa.PrivateKey

	mu         sync.Mutex
	issuer     string // what discovery says; the server's URL by default
	kids       []string
	jwksReads  int
	challenges map[string]string // code -> PKCE challenge
	idTokens   map[string]string // code -> id_token to hand out
	basicAuth  string
}

func newFakeIdP(t *testing.T) *fakeIdP {
	t.Helper()
	f := &fakeIdP{kids: []string{"rsa-1", "ec-1", "weak-1"}, challenges: map[string]string{}, idTokens: map[string]string{}}
	var err error
	if f.rsaKey, err = rsa.GenerateKey(rand.Reader, 2048); err != nil {
		t.Fatal(err)
	}
	if f.ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader); err != nil {
		t.Fatal(err)
	}
	if f.weak, err = rsa.GenerateKey(rand.Reader, 1024); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		iss := f.issuer
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "authorization_endpoint": f.srv.URL + "/authorize",
			"token_endpoint": f.srv.URL + "/token", "jwks_uri": f.srv.URL + "/jwks"})
	})
	mux.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.jwksReads++
		var keys []map[string]string
		for _, kid := range f.kids {
			switch kid {
			case "rsa-1", "rsa-2":
				keys = append(keys, rsaJWK(kid, &f.rsaKey.PublicKey))
			case "weak-1":
				keys = append(keys, rsaJWK(kid, &f.weak.PublicKey))
			case "ec-1":
				keys = append(keys, map[string]string{"kty": "EC", "kid": kid, "use": "sig", "crv": "P-256",
					"x": b64(f.ecKey.PublicKey.X.FillBytes(make([]byte, 32))), "y": b64(f.ecKey.PublicKey.Y.FillBytes(make([]byte, 32)))})
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		user, pass, _ := r.BasicAuth()
		f.basicAuth = user + ":" + pass
		code := r.PostForm.Get("code")
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		if f.challenges[code] == "" || f.challenges[code] != base64.RawURLEncoding.EncodeToString(sum[:]) {
			http.Error(w, "invalid_grant", http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"id_token": f.idTokens[code], "token_type": "Bearer"})
	})
	f.srv = httptest.NewServer(mux)
	f.issuer = f.srv.URL
	t.Cleanup(f.srv.Close)
	return f
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func rsaJWK(kid string, k *rsa.PublicKey) map[string]string {
	return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
}

const clientID, clientSecret = "openbastion", "s3cret"

func (f *fakeIdP) provider(t *testing.T) *infrastructure.OIDCProvider {
	t.Helper()
	p, err := infrastructure.NewOIDCProvider(context.Background(), infrastructure.OIDCConfig{Issuer: f.srv.URL, ClientID: clientID,
		ClientSecret: clientSecret, RedirectURL: "http://127.0.0.1:5173/oidc/callback"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// claims is a valid ID token's payload for this client, nonce "n1".
func (f *fakeIdP) claims() jwt.MapClaims { return f.claimsAt(f.srv.URL) }

// claimsAt is claims from issuer.
func (f *fakeIdP) claimsAt(issuer string) jwt.MapClaims {
	now := time.Now()
	return jwt.MapClaims{"iss": issuer, "aud": clientID, "sub": "subject-1", "nonce": "n1", "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "name": "Alice", "groups": []string{"admins"}}
}

func (f *fakeIdP) sign(t *testing.T, method jwt.SigningMethod, kid string, key any, c jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(method, c)
	if kid != "" {
		tok.Header["kid"] = kid
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestOIDCProvider_AValidIDTokenNamesTheSubjectAndItsGroups(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	for name, raw := range map[string]string{
		"RS256": f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, f.claims()),
		"ES256": f.sign(t, jwt.SigningMethodES256, "ec-1", f.ecKey, f.claims()),
	} {
		id, err := p.VerifyIDToken(context.Background(), raw, "n1")
		if err != nil || id.Subject != "subject-1" || id.Name != "Alice" || len(id.Groups) != 1 || id.Groups[0] != "admins" {
			t.Fatalf("%s: %+v %v", name, id, err)
		}
	}
	// aud as a list holding this client, azp this client: valid.
	c := f.claims()
	c["aud"], c["azp"] = []string{"other", clientID}, clientID
	if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); err != nil {
		t.Fatalf("aud list with this client: %v", err)
	}
	// No groups claim: no groups, not an error.
	c = f.claims()
	delete(c, "groups")
	if id, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); err != nil || id.Groups != nil {
		t.Fatalf("no groups: %+v %v", id, err)
	}
}

func TestOIDCProvider_EveryForgedOrMisdirectedIDTokenIsRefused(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	with := func(k string, v any) jwt.MapClaims {
		c := f.claims()
		if v == nil {
			delete(c, k)
		} else {
			c[k] = v
		}
		return c
	}
	rs := func(c jwt.MapClaims) string { return f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c) }
	pubDER, _ := x509.MarshalPKIXPublicKey(&f.rsaKey.PublicKey)
	valid := rs(f.claims())
	parts := strings.Split(valid, ".")
	tamperedPayload, _ := json.Marshal(map[string]any{"iss": f.srv.URL, "aud": clientID, "sub": "subject-ADMIN", "nonce": "n1",
		"iat": time.Now().Unix(), "exp": time.Now().Add(time.Minute).Unix(), "groups": []string{"admins"}})
	other, _ := rsa.GenerateKey(rand.Reader, 2048)
	for name, raw := range map[string]string{
		"alg none":                         f.sign(t, jwt.SigningMethodNone, "rsa-1", jwt.UnsafeAllowNoneSignatureType, f.claims()),
		"HS256 keyed with the public key":  f.sign(t, jwt.SigningMethodHS256, "rsa-1", pubDER, f.claims()),
		"RS256 header on the EC key":       f.sign(t, jwt.SigningMethodRS256, "ec-1", f.rsaKey, f.claims()),
		"ES256 header on the RSA key":      f.sign(t, jwt.SigningMethodES256, "rsa-1", f.ecKey, f.claims()),
		"signed by a key not the provider": f.sign(t, jwt.SigningMethodRS256, "rsa-1", other, f.claims()),
		"a key under 2048 bits":            f.sign(t, jwt.SigningMethodRS256, "weak-1", f.weak, f.claims()),
		"no kid":                           f.sign(t, jwt.SigningMethodRS256, "", f.rsaKey, f.claims()),
		"payload changed after signing":    parts[0] + "." + b64(tamperedPayload) + "." + parts[2],
		"another issuer":                   rs(with("iss", "https://evil.example")),
		"another audience":                 rs(with("aud", "someone-else")),
		"azp of another client":            rs(with("azp", "someone-else")),
		"expired beyond the leeway":        rs(with("exp", time.Now().Add(-2*time.Minute).Unix())),
		"no exp":                           rs(with("exp", nil)),
		"issued in the future":             rs(with("iat", time.Now().Add(5*time.Minute).Unix())),
		"not before the future":            rs(with("nbf", time.Now().Add(5*time.Minute).Unix())),
		"another login's nonce":            rs(with("nonce", "n2")),
		"no nonce":                         rs(with("nonce", nil)),
		"no subject":                       rs(with("sub", "")),
		"groups that are not a list":       rs(with("groups", "admins")),
		"not a JWT":                        "not.a.jwt",
	} {
		if _, err := p.VerifyIDToken(context.Background(), raw, "n1"); !errors.Is(err, application.ErrOIDCRejected) {
			t.Fatalf("%s: got %v, want ErrOIDCRejected", name, err)
		}
	}
	// Within the leeway is still valid.
	if _, err := p.VerifyIDToken(context.Background(), rs(with("exp", time.Now().Add(-30*time.Second).Unix())), "n1"); err != nil {
		t.Fatalf("expired 30 s ago, within the leeway: %v", err)
	}
}

func TestOIDCProvider_ARotatedKeyIsFound_AndUnknownKidsDoNotHammerTheProvider(t *testing.T) {
	f := newFakeIdP(t)
	now := time.Now()
	p := f.provider(t).WithClock(func() time.Time { return now })
	f.mu.Lock()
	reads := f.jwksReads
	f.kids = append(f.kids, "rsa-2") // the provider rotates: same key material, new kid
	f.mu.Unlock()
	// Within the reload interval, an unknown kid does not make the keys be read again.
	if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-2", f.rsaKey, f.claims()), "n1"); err == nil {
		t.Fatal("an unknown kid accepted without reading the keys")
	}
	for i := 0; i < 20; i++ {
		_, _ = p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "nope", f.rsaKey, f.claims()), "n1")
	}
	f.mu.Lock()
	if f.jwksReads != reads {
		t.Fatalf("the keys were read %d more times within a minute", f.jwksReads-reads)
	}
	f.mu.Unlock()
	now = now.Add(61 * time.Second)
	if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-2", f.rsaKey, f.claims()), "n1"); err != nil {
		t.Fatalf("after a minute, the rotated key is read and found: %v", err)
	}
}

func TestOIDCProvider_TheCodeFlowUsesPKCEStateNonceAndTheClientSecret(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	u, err := url.Parse(p.AuthorizeURL("st1", "n1", "verifier-0123456789-0123456789-0123456789"))
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	sum := sha256.Sum256([]byte("verifier-0123456789-0123456789-0123456789"))
	for k, want := range map[string]string{"response_type": "code", "client_id": clientID, "state": "st1", "nonce": "n1",
		"redirect_uri": "http://127.0.0.1:5173/oidc/callback", "code_challenge_method": "S256", "code_challenge": b64(sum[:])} {
		if q.Get(k) != want {
			t.Fatalf("%s = %q, want %q", k, q.Get(k), want)
		}
	}
	if !strings.Contains(q.Get("scope"), "openid") {
		t.Fatalf("scope %q has no openid", q.Get("scope"))
	}
	f.mu.Lock()
	f.challenges["code-1"] = q.Get("code_challenge")
	f.idTokens["code-1"] = "the-id-token"
	f.mu.Unlock()
	if _, err := p.Exchange(context.Background(), "code-1", "a-wrong-verifier"); err == nil {
		t.Fatal("the code exchanged with the wrong PKCE verifier")
	}
	got, err := p.Exchange(context.Background(), "code-1", "verifier-0123456789-0123456789-0123456789")
	if err != nil || got != "the-id-token" {
		t.Fatalf("exchange: %q %v", got, err)
	}
	if f.basicAuth != clientID+":"+clientSecret {
		t.Fatalf("client authentication %q", f.basicAuth)
	}
}

func TestNewOIDCProvider_RefusesAProviderThatCannotBeTrusted(t *testing.T) {
	f := newFakeIdP(t)
	base := infrastructure.OIDCConfig{Issuer: f.srv.URL, ClientID: clientID, ClientSecret: clientSecret, RedirectURL: "http://127.0.0.1:5173/cb"}
	for name, cfg := range map[string]infrastructure.OIDCConfig{
		"issuer over http, not loopback":   {Issuer: "http://idp.example", ClientID: clientID, ClientSecret: clientSecret, RedirectURL: base.RedirectURL},
		"redirect over http, not loopback": {Issuer: base.Issuer, ClientID: clientID, ClientSecret: clientSecret, RedirectURL: "http://bastion.example/cb"},
		"no client secret":                 {Issuer: base.Issuer, ClientID: clientID, RedirectURL: base.RedirectURL},
		"an issuer that is not a URL":      {Issuer: "idp", ClientID: clientID, ClientSecret: clientSecret, RedirectURL: base.RedirectURL},
	} {
		if _, err := infrastructure.NewOIDCProvider(context.Background(), cfg, nil); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
	f.mu.Lock()
	f.issuer = "https://someone-else.example"
	f.mu.Unlock()
	if _, err := infrastructure.NewOIDCProvider(context.Background(), base, nil); err == nil || !strings.Contains(err.Error(), "issuer") {
		t.Fatalf("a discovery document naming another issuer: %v", err)
	}
}

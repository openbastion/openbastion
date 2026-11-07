package infrastructure

// The OpenID Connect client (ADR-0035): discovery, the provider's keys, the authorization URL,
// the code exchange and the verification of the ID token — standard library and golang-jwt.

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
)

// OIDCConfig is what the deployment says about its provider.
type OIDCConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	RedirectURL  string
	GroupsClaim  string // "groups" when empty
	// TenantID makes it an Entra ID provider (ADR-0079): the issuer is that tenant's v2 issuer,
	// and every ID token carries that tenant, with all its groups. Empty: a generic provider.
	TenantID string
}

// OIDCProvider is application.OIDCProvider against one OpenID Connect provider.
type OIDCProvider struct {
	cfg       OIDCConfig
	client    *http.Client
	authorize string
	token     string
	jwksURI   string
	now       func() time.Time

	mu       sync.Mutex
	keys     map[string]any // kid -> *rsa.PublicKey | *ecdsa.PublicKey
	lastLoad time.Time
}

// Leeway is the clock skew tolerated on exp, iat and nbf.
const Leeway = 60 * time.Second

// keyReloadInterval bounds how often an unknown kid makes the provider's keys be read again.
const keyReloadInterval = time.Minute

// secureURL: https, or http to a loopback address (development).
func secureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an absolute URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" {
		host := u.Hostname()
		if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() || host == "localhost" {
			return nil
		}
	}
	return fmt.Errorf("%s must be https (http only to a loopback address)", u.Redacted())
}

// NewOIDCProvider discovers the provider: its document must name exactly cfg.Issuer, and every
// endpoint it gives must be secure. It reads the provider's keys once.
func NewOIDCProvider(ctx context.Context, cfg OIDCConfig, client *http.Client) (*OIDCProvider, error) {
	for name, v := range map[string]string{"OIDC_ISSUER": cfg.Issuer, "OIDC_REDIRECT_URL": cfg.RedirectURL} {
		if err := secureURL(v); err != nil {
			return nil, fmt.Errorf("%s: %v", name, err)
		}
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, errors.New("OIDC_CLIENT_ID and OIDC_CLIENT_SECRET are required")
	}
	if cfg.TenantID != "" {
		if err := checkEntraIssuer(cfg.TenantID, cfg.Issuer); err != nil {
			return nil, err
		}
	}
	if cfg.GroupsClaim == "" {
		cfg.GroupsClaim = "groups"
	}
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Second}
	}
	p := &OIDCProvider{cfg: cfg, client: client, now: time.Now}
	var doc struct {
		Issuer        string `json:"issuer"`
		Authorization string `json:"authorization_endpoint"`
		Token         string `json:"token_endpoint"`
		JWKS          string `json:"jwks_uri"`
	}
	if err := p.getJSON(ctx, strings.TrimRight(cfg.Issuer, "/")+"/.well-known/openid-configuration", &doc); err != nil {
		return nil, fmt.Errorf("discovering the provider: %w", err)
	}
	if doc.Issuer != cfg.Issuer {
		return nil, fmt.Errorf("the provider says its issuer is %q, not %q — refusing it", doc.Issuer, cfg.Issuer)
	}
	for name, v := range map[string]string{"authorization_endpoint": doc.Authorization, "token_endpoint": doc.Token, "jwks_uri": doc.JWKS} {
		if err := secureURL(v); err != nil {
			return nil, fmt.Errorf("the provider's %s: %v", name, err)
		}
	}
	p.authorize, p.token, p.jwksURI = doc.Authorization, doc.Token, doc.JWKS
	if err := p.loadKeys(ctx); err != nil {
		return nil, err
	}
	return p, nil
}

// WithClock replaces the clock; for tests.
func (p *OIDCProvider) WithClock(now func() time.Time) *OIDCProvider {
	p.now = now
	return p
}

func (p *OIDCProvider) getJSON(ctx context.Context, u string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return err
	}
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: status %d", u, resp.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(out)
}

// AuthorizeURL is where the browser is sent: the code flow, with PKCE (S256), state and nonce.
func (p *OIDCProvider) AuthorizeURL(state, nonce, verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	scope := "openid profile email " + p.cfg.GroupsClaim
	if p.cfg.TenantID != "" {
		// Entra ID has no groups scope: the groups are in the token by the application's own
		// configuration (groupMembershipClaims), and an unknown scope is refused (ADR-0079).
		scope = "openid profile email"
	}
	q := url.Values{
		"response_type":         {"code"},
		"client_id":             {p.cfg.ClientID},
		"redirect_uri":          {p.cfg.RedirectURL},
		"scope":                 {scope},
		"state":                 {state},
		"nonce":                 {nonce},
		"code_challenge":        {base64.RawURLEncoding.EncodeToString(sum[:])},
		"code_challenge_method": {"S256"},
	}
	sep := "?"
	if strings.Contains(p.authorize, "?") {
		sep = "&"
	}
	return p.authorize + sep + q.Encode()
}

// Exchange trades the code for the ID token, proving the PKCE verifier and the client secret.
func (p *OIDCProvider) Exchange(ctx context.Context, code, verifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.cfg.RedirectURL},
		"code_verifier": {verifier},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.token, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(url.QueryEscape(p.cfg.ClientID), url.QueryEscape(p.cfg.ClientSecret))
	resp, err := p.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("the provider refused the code: status %d", resp.StatusCode)
	}
	var out struct {
		IDToken string `json:"id_token"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&out); err != nil || out.IDToken == "" {
		return "", errors.New("the provider's answer holds no id_token")
	}
	return out.IDToken, nil
}

type idClaims struct {
	Nonce             string `json:"nonce"`
	AuthorizedParty   string `json:"azp"`
	Name              string `json:"name"`
	PreferredUsername string `json:"preferred_username"`
	jwt.RegisteredClaims
}

// VerifyIDToken checks the ID token field by field (ADR-0035 rule 4) and returns who it names
// and the groups it says they belong to.
func (p *OIDCProvider) VerifyIDToken(ctx context.Context, raw, nonce string) (application.OIDCIdentity, error) {
	var c idClaims
	parser := jwt.NewParser(
		jwt.WithValidMethods([]string{"RS256", "ES256"}),
		jwt.WithIssuer(p.cfg.Issuer),
		jwt.WithAudience(p.cfg.ClientID),
		jwt.WithExpirationRequired(),
		jwt.WithIssuedAt(),
		jwt.WithLeeway(Leeway),
		jwt.WithTimeFunc(p.now),
	)
	tok, err := parser.ParseWithClaims(raw, &c, func(t *jwt.Token) (any, error) {
		kid, _ := t.Header["kid"].(string)
		key, err := p.key(ctx, kid)
		if err != nil {
			return nil, err
		}
		// The key decides the algorithm: an RSA key verifies RS256 only, an EC key ES256 only.
		switch key.(type) {
		case *rsa.PublicKey:
			if t.Method.Alg() != "RS256" {
				return nil, fmt.Errorf("key %q is RSA, the token says %s", kid, t.Method.Alg())
			}
		case *ecdsa.PublicKey:
			if t.Method.Alg() != "ES256" {
				return nil, fmt.Errorf("key %q is EC, the token says %s", kid, t.Method.Alg())
			}
		}
		return key, nil
	})
	if err != nil || !tok.Valid {
		return application.OIDCIdentity{}, fmt.Errorf("%w: %v", application.ErrOIDCRejected, err)
	}
	if c.AuthorizedParty != "" && c.AuthorizedParty != p.cfg.ClientID {
		return application.OIDCIdentity{}, fmt.Errorf("%w: azp is not this client", application.ErrOIDCRejected)
	}
	if c.Nonce == "" || c.Nonce != nonce {
		return application.OIDCIdentity{}, fmt.Errorf("%w: the nonce is not this login's", application.ErrOIDCRejected)
	}
	if c.Subject == "" {
		return application.OIDCIdentity{}, fmt.Errorf("%w: no subject", application.ErrOIDCRejected)
	}
	groups, err := p.groups(raw)
	if err != nil {
		return application.OIDCIdentity{}, err
	}
	name := c.Name
	if name == "" {
		name = c.PreferredUsername
	}
	return application.OIDCIdentity{Subject: c.Subject, Name: name, Groups: groups}, nil
}

// groups reads the configured claim from a token whose signature is already verified: a list
// of strings, or absent.
func (p *OIDCProvider) groups(raw string) ([]string, error) {
	parts := strings.Split(raw, ".")
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("%w: payload", application.ErrOIDCRejected)
	}
	var all map[string]json.RawMessage
	if err := json.Unmarshal(payload, &all); err != nil {
		return nil, fmt.Errorf("%w: payload", application.ErrOIDCRejected)
	}
	if p.cfg.TenantID != "" {
		if err := entraClaims(all, p.cfg.TenantID, p.cfg.GroupsClaim); err != nil {
			return nil, err
		}
	}
	v, ok := all[p.cfg.GroupsClaim]
	if !ok {
		return nil, nil
	}
	var groups []string
	if err := json.Unmarshal(v, &groups); err != nil {
		return nil, fmt.Errorf("%w: the %s claim is not a list of strings", application.ErrOIDCRejected, p.cfg.GroupsClaim)
	}
	return groups, nil
}

func (p *OIDCProvider) key(ctx context.Context, kid string) (any, error) {
	p.mu.Lock()
	k, ok := p.keys[kid]
	stale := p.now().Sub(p.lastLoad) >= keyReloadInterval
	p.mu.Unlock()
	if ok {
		return k, nil
	}
	if !stale {
		return nil, fmt.Errorf("no key %q", kid)
	}
	if err := p.loadKeys(ctx); err != nil {
		return nil, err
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if k, ok := p.keys[kid]; ok {
		return k, nil
	}
	return nil, fmt.Errorf("no key %q", kid)
}

type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// loadKeys reads the provider's signing keys: RSA (2048 bits at least) and EC P-256. Any
// other key is ignored, never guessed at.
func (p *OIDCProvider) loadKeys(ctx context.Context) error {
	var set struct {
		Keys []jwk `json:"keys"`
	}
	if err := p.getJSON(ctx, p.jwksURI, &set); err != nil {
		return fmt.Errorf("reading the provider's keys: %w", err)
	}
	keys := map[string]any{}
	for _, k := range set.Keys {
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		switch k.Kty {
		case "RSA":
			n, err1 := base64.RawURLEncoding.DecodeString(k.N)
			e, err2 := base64.RawURLEncoding.DecodeString(k.E)
			if err1 != nil || err2 != nil || len(n) < 256 || len(e) == 0 || len(e) > 4 {
				continue
			}
			keys[k.Kid] = &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}
		case "EC":
			if k.Crv != "P-256" {
				continue
			}
			x, err1 := base64.RawURLEncoding.DecodeString(k.X)
			y, err2 := base64.RawURLEncoding.DecodeString(k.Y)
			if err1 != nil || err2 != nil {
				continue
			}
			pub := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
			if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
				continue
			}
			keys[k.Kid] = pub
		}
	}
	p.mu.Lock()
	p.keys, p.lastLoad = keys, p.now()
	p.mu.Unlock()
	return nil
}

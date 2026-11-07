package infrastructure_test

// ADR-0079: an Entra ID provider is an OIDC provider bound to one declared tenant. Its issuer is
// the v2 issuer of that tenant exactly; a token of another tenant, or without one, is refused; a
// token whose groups are elsewhere (an overage) is refused, and the reference it names is never
// fetched. No request leaves the test: the client below sends everything to the fake provider.

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/golang-jwt/jwt/v5"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

const (
	tenantA = "11111111-2222-4333-8444-555555555555"
	tenantB = "99999999-8888-4777-8666-555555555555"
	// tenantHex has letters: its upper case is another string.
	tenantHex = "abcdef01-2345-4678-9abc-def012345678"
)

// toFake sends every request to the fake provider, whatever its host, and remembers the hosts
// and paths asked: what the provider was made to fetch.
type toFake struct {
	target *url.URL
	mu     sync.Mutex
	asked  []string
}

func (r *toFake) RoundTrip(req *http.Request) (*http.Response, error) {
	r.mu.Lock()
	r.asked = append(r.asked, req.URL.Host+req.URL.Path)
	r.mu.Unlock()
	out := req.Clone(req.Context())
	out.URL.Scheme, out.URL.Host = r.target.Scheme, r.target.Host
	// The fake serves its documents at the root; Entra's are under /<tenant>/v2.0.
	if i := strings.Index(out.URL.Path, "/v2.0"); i >= 0 {
		out.URL.Path = out.URL.Path[i+len("/v2.0"):]
	}
	out.Host = ""
	return http.DefaultTransport.RoundTrip(out)
}

func (r *toFake) requests() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.asked...)
}

func entraProvider(t *testing.T, f *fakeIdP, tenant string) (*infrastructure.OIDCProvider, *toFake, error) {
	t.Helper()
	issuer := "https://login.microsoftonline.com/" + tenant + "/v2.0"
	f.mu.Lock()
	f.issuer = issuer
	f.mu.Unlock()
	target, _ := url.Parse(f.srv.URL)
	rt := &toFake{target: target}
	p, err := infrastructure.NewOIDCProvider(context.Background(), infrastructure.OIDCConfig{Issuer: issuer, ClientID: clientID,
		ClientSecret: clientSecret, RedirectURL: "http://127.0.0.1:5173/oidc/callback", TenantID: tenant}, &http.Client{Transport: rt})
	return p, rt, err
}

func entraClaims(tenant string) jwt.MapClaims {
	c := jwt.MapClaims{}
	for k, v := range (&fakeIdP{}).claimsAt("https://login.microsoftonline.com/" + tenant + "/v2.0") {
		c[k] = v
	}
	c["tid"] = tenant
	return c
}

func TestEntra_AValidTokenOfTheDeclaredTenant_NamesItsSubjectAndGroups(t *testing.T) {
	f := newFakeIdP(t)
	p, _, err := entraProvider(t, f, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	id, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, entraClaims(tenantA)), "n1")
	if err != nil || id.Subject != "subject-1" || len(id.Groups) != 1 || id.Groups[0] != "admins" {
		t.Fatalf("%+v %v", id, err)
	}
}

func TestEntra_ATokenWithoutTheDeclaredTenant_IsRefused(t *testing.T) {
	f := newFakeIdP(t)
	p, _, err := entraProvider(t, f, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	noTid := entraClaims(tenantA)
	delete(noTid, "tid")
	emptyTid := entraClaims(tenantA)
	emptyTid["tid"] = ""
	otherTid := entraClaims(tenantA)
	otherTid["tid"] = tenantB
	numberTid := entraClaims(tenantA)
	numberTid["tid"] = 42
	for name, c := range map[string]jwt.MapClaims{"no tid": noTid, "an empty tid": emptyTid, "another tenant": otherTid, "a tid not a string": numberTid} {
		if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); !errors.Is(err, application.ErrOIDCRejected) {
			t.Fatalf("%s: %v, want ErrOIDCRejected", name, err)
		}
	}
	// The same tenant in upper case is the same tenant.
	ph, _, err := entraProvider(t, f, tenantHex)
	if err != nil {
		t.Fatal(err)
	}
	upper := entraClaims(tenantHex)
	upper["tid"] = strings.ToUpper(tenantHex)
	if _, err := ph.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, upper), "n1"); err != nil {
		t.Fatalf("the tenant in upper case: %v", err)
	}
}

func TestEntra_AGroupsOverage_IsRefused_AndItsReferenceIsNeverFetched(t *testing.T) {
	f := newFakeIdP(t)
	p, rt, err := entraProvider(t, f, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	before := len(rt.requests())
	graph := "https://graph.microsoft.com/v1.0/users/subject-1/getMemberObjects"
	overages := map[string]func(jwt.MapClaims){
		"_claim_names and _claim_sources": func(c jwt.MapClaims) {
			delete(c, "groups")
			c["_claim_names"] = map[string]string{"groups": "src1"}
			c["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": graph}}
		},
		"_claim_names alone": func(c jwt.MapClaims) { c["_claim_names"] = map[string]string{"groups": "src1"} },
		"hasgroups": func(c jwt.MapClaims) { delete(c, "groups"); c["hasgroups"] = true },
	}
	for name, change := range overages {
		c := entraClaims(tenantA)
		change(c)
		if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); !errors.Is(err, application.ErrOIDCRejected) {
			t.Fatalf("%s: %v, want ErrOIDCRejected", name, err)
		}
	}
	for _, r := range rt.requests()[before:] {
		if strings.Contains(r, "graph.microsoft.com") {
			t.Fatalf("the reference of an overage was fetched: %s", r)
		}
	}
	// Distributed claims unrelated to groups are valid OIDC: _claim_sources alone, or
	// referenced by _claim_names for another claim, is not a groups overage.
	unrelated := map[string]jwt.MapClaims{
		"_claim_sources alone": func() jwt.MapClaims {
			c := entraClaims(tenantA)
			c["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": graph}}
			return c
		}(),
		"another claim uses _claim_sources": func() jwt.MapClaims {
			c := entraClaims(tenantA)
			c["_claim_names"] = map[string]string{"email": "src1"}
			c["_claim_sources"] = map[string]any{"src1": map[string]string{"endpoint": graph}}
			return c
		}(),
		"hasgroups false": func() jwt.MapClaims {
			c := entraClaims(tenantA)
			c["hasgroups"] = false
			return c
		}(),
	}
	for name, c := range unrelated {
		if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); err != nil {
			t.Fatalf("%s: %v, want a valid token", name, err)
		}
	}
}

func TestEntra_AGenericProvider_IgnoresTenantAndOverage(t *testing.T) {
	f := newFakeIdP(t)
	p := f.provider(t)
	c := f.claims()
	c["tid"], c["hasgroups"] = tenantB, true
	if _, err := p.VerifyIDToken(context.Background(), f.sign(t, jwt.SigningMethodRS256, "rsa-1", f.rsaKey, c), "n1"); err != nil {
		t.Fatalf("a generic provider is not the Entra profile: %v", err)
	}
}

func TestEntra_ATenantOrIssuerThatIsNotOneDeclaredTenant_RefusesTheProvider(t *testing.T) {
	for name, tc := range map[string]struct{ tenant, issuer string }{
		"common":                  {"common", "https://login.microsoftonline.com/common/v2.0"},
		"organizations":           {"organizations", "https://login.microsoftonline.com/organizations/v2.0"},
		"consumers":               {"consumers", "https://login.microsoftonline.com/consumers/v2.0"},
		"a domain name":           {"contoso.onmicrosoft.com", "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"},
		"a GUID in upper case":    {strings.ToUpper(tenantHex), "https://login.microsoftonline.com/" + strings.ToUpper(tenantHex) + "/v2.0"},
		"the issuer of another":   {tenantA, "https://login.microsoftonline.com/" + tenantB + "/v2.0"},
		"the v1 issuer":           {tenantA, "https://sts.windows.net/" + tenantA + "/"},
		"http":                    {tenantA, "http://login.microsoftonline.com/" + tenantA + "/v2.0"},
		"a trailing slash":        {tenantA, "https://login.microsoftonline.com/" + tenantA + "/v2.0/"},
		"another host, same path": {tenantA, "https://login.example.com/" + tenantA + "/v2.0"},
	} {
		_, err := infrastructure.NewOIDCProvider(context.Background(), infrastructure.OIDCConfig{Issuer: tc.issuer, ClientID: clientID,
			ClientSecret: clientSecret, RedirectURL: "http://127.0.0.1:5173/oidc/callback", TenantID: tc.tenant}, &http.Client{Transport: failing{}})
		// Refused by the check itself, before any network: never by the transport that fails.
		if err == nil || strings.Contains(err.Error(), "no network") {
			t.Fatalf("%s: %v, want a refusal before any request", name, err)
		}
	}
}

// failing refuses every request: the checks above come before any network.
type failing struct{}

func (failing) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("no network in this test")
}

func TestProvidersFile_AnEntraEntry_IsOneDeclaredTenantAndItsV2Issuer(t *testing.T) {
	entra := func(extra string) string {
		return `{"oidc": [{"id": "corp", "label": "Corp", "issuer": "https://login.microsoftonline.com/` + tenantA + `/v2.0", "client_id": "ob", "client_secret_file": "/s", "redirect_url": "https://ob.example/ui/", "role_map_file": "/r"` + extra + `}]}`
	}
	f, err := infrastructure.LoadProvidersFile(writeProviders(t, entra(`, "profile": "entra", "tenant_id": "`+tenantA+`"`), 0o644))
	if err != nil || f.OIDC[0].Profile != infrastructure.ProfileEntra || f.OIDC[0].TenantID != tenantA {
		t.Fatalf("a valid Entra entry: %+v %v", f, err)
	}
	for name, c := range map[string]struct{ extra, want string }{
		"no tenant":                    {`, "profile": "entra"`, "tenant_id must be the tenant's GUID"},
		"common":                       {`, "profile": "entra", "tenant_id": "common"`, "tenant_id must be the tenant's GUID"},
		"organizations":                {`, "profile": "entra", "tenant_id": "organizations"`, "tenant_id must be the tenant's GUID"},
		"consumers":                    {`, "profile": "entra", "tenant_id": "consumers"`, "tenant_id must be the tenant's GUID"},
		"another tenant's issuer":      {`, "profile": "entra", "tenant_id": "` + tenantB + `"`, "is exactly https://login.microsoftonline.com/" + tenantB},
		"a tenant without the profile": {`, "tenant_id": "` + tenantA + `"`, "tenant_id is for the profile"},
		"an unknown profile":           {`, "profile": "saml"`, `profile is "oidc" or "entra"`},
	} {
		_, err := infrastructure.LoadProvidersFile(writeProviders(t, entra(c.extra), 0o644))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: %v, want %q", name, err, c.want)
		}
		if !strings.Contains(err.Error(), `oidc "corp"`) {
			t.Fatalf("%s: the refusal does not name the entry: %v", name, err)
		}
	}
	// The generic profile, named or not, keeps its behaviour.
	if _, err := infrastructure.LoadProvidersFile(writeProviders(t, strings.Replace(entra(`, "profile": "oidc"`), "login.microsoftonline.com/"+tenantA+"/v2.0", "idp.example", 1), 0o644)); err != nil {
		t.Fatalf("profile oidc: %v", err)
	}
}

func TestEntra_TheAuthorizationAsksNoGroupsScope(t *testing.T) {
	f := newFakeIdP(t)
	p, _, err := entraProvider(t, f, tenantA)
	if err != nil {
		t.Fatal(err)
	}
	u, _ := url.Parse(p.AuthorizeURL("s", "n", "v"))
	if got := u.Query().Get("scope"); got != "openid profile email" {
		t.Fatalf("scope %q, want openid profile email", got)
	}
	if got, _ := url.Parse(newFakeIdP(t).provider(t).AuthorizeURL("s", "n", "v")); !strings.HasSuffix(got.Query().Get("scope"), " groups") {
		t.Fatalf("a generic provider asks its groups claim as a scope: %q", got.Query().Get("scope"))
	}
}

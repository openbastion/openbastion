package integration_test

// ADR-0076 across real processes: one Authentication Service, under PostgreSQL, behind a real
// Gateway, federates at once a real OpenLDAP, a real Active Directory (Samba) and two real OIDC
// providers (Dex, pinned by digest) — and each account is bound to its provider. The two Dex give
// their user the same `sub`: two accounts, never one. A callback is exchanged where it was
// started; a directory is never chosen for the user; the accounts made before are adopted by the
// entry that says so, and by no other.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

// dexImage is Dex v2.46.0, pinned by the digest of its index (docker buildx imagetools inspect).
const dexImage = "ghcr.io/dexidp/dex:v2.46.0@sha256:933fcd3f523338c847b88ef84a7145fb2fcb7b9917f08418612afeaaa2001777"

const dexClientSecret = "dex-client-secret-0123456789abcdef"

// dexRedirect is where Dex sends the browser back: nothing listens there, the test reads the code
// from the redirection.
const dexRedirect = "http://127.0.0.1:19939/ui/"

// startDex runs one Dex on port, its issuer http://127.0.0.1:<port>/dex, with the mockCallback
// connector: a user "Kilgore Trout" in the group "authors", without a login screen. Two Dex give
// that user the same sub.
func startDex(t *testing.T, port string) (issuer string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed — skipping the test against a real OIDC provider")
	}
	issuer = "http://127.0.0.1:" + port + "/dex"
	conf := writeFile(t, t.TempDir(), "config.yaml", fmt.Sprintf(`issuer: %s
storage: {type: memory}
web: {http: 0.0.0.0:%s}
oauth2: {skipApprovalScreen: true}
staticClients:
- id: openbastion
  secret: %s
  name: OpenBastion
  redirectURIs: ['%s']
connectors:
- {type: mockCallback, id: mock, name: Mock}
`, issuer, port, dexClientSecret, dexRedirect), 0o644)
	name := fmt.Sprintf("ob-test-dex-%s-%d", port, time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", name, "-p", "127.0.0.1:"+port+":"+port,
		"-v", conf+":/etc/dex/config.yaml:ro", dexImage, "dex", "serve", "/etc/dex/config.yaml").CombinedOutput(); err != nil {
		t.Fatalf("docker run dex: %v\n%s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", name).Run() })
	waitUntil(t, 60*time.Second, "Dex on "+port, func() bool {
		resp, err := http.Get(issuer + "/.well-known/openid-configuration")
		if err != nil {
			return false
		}
		resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	})
	return issuer
}

// noRedirect is a client that shows each redirection instead of following it.
var noRedirect = &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }, Timeout: 10 * time.Second}

// oidcStartAt is POST /auth/oidc/start at provider: the status, and where to send the browser.
func oidcStartAt(t *testing.T, gatewayURL, provider string) (int, string) {
	t.Helper()
	body := `{}`
	if provider != "" {
		body = `{"provider": "` + provider + `"}`
	}
	resp, err := http.Post(gatewayURL+"/auth/oidc/start", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AuthorizationURL string `json:"authorizationUrl"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.AuthorizationURL
}

// dexCodeFor follows a browser through Dex, from the authorization URL to the redirection back:
// the code and the state it carries.
func dexCodeFor(t *testing.T, authorizationURL string) (code, state string) {
	t.Helper()
	next := authorizationURL
	for i := 0; i < 10; i++ {
		resp, err := noRedirect.Get(next)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		loc, err := resp.Location()
		if err != nil {
			t.Fatalf("Dex stopped redirecting at %s: %d", next, resp.StatusCode)
		}
		if strings.HasPrefix(loc.String(), dexRedirect) {
			return loc.Query().Get("code"), loc.Query().Get("state")
		}
		next = loc.String()
	}
	t.Fatal("Dex did not send the browser back")
	return "", ""
}

// dexLogin is a whole federated login at provider through the Gateway: the status and the body.
func dexLogin(t *testing.T, gatewayURL, provider string) (int, string) {
	t.Helper()
	status, u := oidcStartAt(t, gatewayURL, provider)
	if status != http.StatusOK {
		t.Fatalf("start at %q: %d", provider, status)
	}
	code, state := dexCodeFor(t, u)
	return oidcCallback(t, gatewayURL, code, state)
}

// ldapLoginAt is POST /auth/ldap/login at directory ("" names none).
func ldapLoginAt(t *testing.T, gatewayURL, directory, username, password string) (int, string) {
	t.Helper()
	fields := map[string]string{"username": username, "password": password}
	if directory != "" {
		fields["directory"] = directory
	}
	b, _ := json.Marshal(fields)
	resp, err := http.Post(gatewayURL+"/auth/ldap/login", "application/json", strings.NewReader(string(b)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func accessToken(body string) string {
	var tok struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.Unmarshal([]byte(body), &tok)
	return tok.AccessToken
}

func getJSON(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(raw)
}

func TestIdentityProviders_FourProvidersAtOnce_EachAccountBoundToItsOwn(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed integration test (see /NOTES_SANDBOX.md)")
	}
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-76")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-76")
	signing := testKMSKeyHex(t)

	// The two directories, as in ldap_flow_test.go: each has its own alice, with its own password.
	pw := map[string]string{"svc": "Svc-Bastion-pass 1", "alice": "Alice-Pass 0123", "bob": "Bob-Pass-0123", "carol": "Carol-Pass-0123", "twin": "Twin-Pass-0123", "admin": "Admin-Pass-0123"}
	ldapSeed := t.TempDir()
	writeDirectoryPKI(t, ldapSeed)
	data := openLDAPData
	for k, v := range pw {
		data = strings.ReplaceAll(data, "{{"+k+"}}", v)
	}
	writeFile(t, ldapSeed, "data.ldif", data, 0o644)
	writeFile(t, ldapSeed, "admin-password", pw["admin"], 0o644)
	ldapContainer, ldapAddr := startDirectory(t, root, "openldap", ldapSeed, "389")

	adPw := map[string]string{"admin": "Adm1n-Pass-0123!", "svc": "Svc-Bastion-0123!", "alice": "Alice-AD-Pass-0123!"}
	adSeed := t.TempDir()
	writeDirectoryPKI(t, adSeed)
	writeFile(t, adSeed, "admin-password", adPw["admin"], 0o644)
	writeFile(t, adSeed, "setup.sh", fmt.Sprintf(`set -e
samba-tool user create svc-bastion '%s' >/dev/null
samba-tool user create alice '%s' --given-name=Alice --surname=AD >/dev/null
samba-tool group add bastion-admins >/dev/null
samba-tool group addmembers bastion-admins alice >/dev/null
`, adPw["svc"], adPw["alice"]), 0o644)
	adContainer, adAddr := startDirectory(t, root, "samba", adSeed, "636")

	issuerA, issuerB := startDex(t, "15561"), startDex(t, "15562")
	waitUntil(t, 60*time.Second, "slapd to start", func() bool { return strings.Contains(directoryLogs(ldapContainer), "slapd starting") })
	waitUntil(t, 180*time.Second, "the domain controller to be provisioned", func() bool {
		return strings.Contains(directoryLogs(adContainer), "samba: ready to start")
	})

	conf := t.TempDir()
	secret := writeFile(t, conf, "client-secret", dexClientSecret+"\n", 0o600)
	entry := func(id, label, issuer, roles string, adopt bool) string {
		return fmt.Sprintf(`{"id": %q, "label": %q, "issuer": %q, "client_id": "openbastion", "client_secret_file": %q, "redirect_url": %q, "role_map_file": %q, "adopt_legacy_accounts": %v}`,
			id, label, issuer, secret, dexRedirect, writeFile(t, conf, id+"-roles.json", roles, 0o600), adopt)
	}
	directories := fmt.Sprintf(`[
	{"id": "openldap", "label": "OpenLDAP", "url": "ldap://%s", "ca_file": %q, "schema": "rfc", "bind_dn": "cn=svc-bastion,ou=service,dc=example,dc=test", "bind_password_file": %q, "user_base_dn": "dc=example,dc=test", "group_base_dn": "ou=groups,dc=example,dc=test", "role_map_file": %q},
	{"id": "samba-ad", "label": "Active Directory", "url": "ldaps://%s", "ca_file": %q, "schema": "ad", "bind_dn": "CN=svc-bastion,CN=Users,DC=example,DC=test", "bind_password_file": %q, "user_base_dn": "CN=Users,DC=example,DC=test", "group_base_dn": "DC=example,DC=test", "role_map_file": %q}]`,
		ldapAddr, filepath.Join(ldapSeed, "ca.pem"), writeFile(t, conf, "ldap-bind", pw["svc"], 0o600),
		writeFile(t, conf, "ldap-roles.json", `{"cn=bastion-admins,ou=groups,dc=example,dc=test": ["platform-admin"]}`, 0o600),
		adAddr, filepath.Join(adSeed, "ca.pem"), writeFile(t, conf, "ad-bind", adPw["svc"], 0o600),
		writeFile(t, conf, "ad-roles.json", `{"CN=bastion-admins,CN=Users,DC=example,DC=test": ["vault-admin"]}`, 0o600))
	providersFile := func(name string, adoptA bool) string {
		return writeFile(t, conf, name, fmt.Sprintf(`{"oidc": [%s, %s], "directories": %s}`,
			entry("dex-a", "Dex A", issuerA, `{"authors": ["platform-admin"]}`, adoptA),
			entry("dex-b", "Dex B", issuerB, `{"authors": ["dba"]}`, false), directories), 0o644)
	}
	base := []string{"DATABASE_URL=" + dsn, "TOKEN_SIGNING_KEY_HEX=" + signing, "SKIP_DEMO_SEED=1"}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	// Before ADR-0076: one provider by its variables — its account is kept under the provider "".
	legacy := startService(t, root, authnBin, "19931", append(append([]string{}, base...), "OIDC_ISSUER="+issuerA, "OIDC_CLIENT_ID=openbastion",
		"OIDC_CLIENT_SECRET="+dexClientSecret, "OIDC_REDIRECT_URL="+dexRedirect, "OIDC_ROLE_MAP_FILE="+writeFile(t, conf, "legacy-roles.json", `{"authors": ["platform-admin"]}`, 0o600))...)
	legacyGateway := startService(t, root, gatewayBin, "19932", "AUTHENTICATION_URL="+legacy.baseURL, "CLIENT_LOGIN_BURST=100")
	status, body := dexLogin(t, legacyGateway.baseURL, "")
	if status != http.StatusOK {
		t.Fatalf("the login by the variables: %d %s", status, body)
	}
	legacyName, _ := whoIs(t, legacy.baseURL, accessToken(body))
	if !strings.HasPrefix(legacyName, "oidc:") || strings.Count(legacyName, ":") != 1 {
		t.Fatalf("the account made by the variables: %q, want oidc:<sub>", legacyName)
	}
	sub := strings.TrimPrefix(legacyName, "oidc:")

	t.Run("the file and the variables together, an id twice, a secret others read: the service does not start, and says no secret", func(t *testing.T) {
		twice := writeFile(t, conf, "twice.json", fmt.Sprintf(`{"oidc": [%s, %s]}`,
			entry("dex-a", "A", issuerA, `{"authors": ["dba"]}`, false), entry("dex-a", "B", issuerB, `{"authors": ["dba"]}`, false)), 0o644)
		openSecret := writeFile(t, conf, "open-secret", dexClientSecret, 0o644)
		leaky := writeFile(t, conf, "leaky.json", strings.Replace(fmt.Sprintf(`{"oidc": [%s]}`, entry("dex-a", "A", issuerA, `{"authors": ["dba"]}`, false)), secret, openSecret, 1), 0o644)
		for name, env := range map[string][]string{
			"the file and OIDC_ISSUER": {"IDENTITY_PROVIDERS_FILE=" + providersFile("p0.json", false), "OIDC_ISSUER=" + issuerA},
			"the file and LDAP_URL":    {"IDENTITY_PROVIDERS_FILE=" + providersFile("p1.json", false), "LDAP_URL=ldap://" + ldapAddr},
			"an id twice":              {"IDENTITY_PROVIDERS_FILE=" + twice},
			"a secret others read":     {"IDENTITY_PROVIDERS_FILE=" + leaky},
			"a file others can write":  {"IDENTITY_PROVIDERS_FILE=" + writeFile(t, conf, "writable.json", `{"oidc": []}`, 0o666)},
		} {
			out := runUntilExit(t, root, authnBin, append(append([]string{"PORT=19933"}, base...), env...)...)
			if !strings.Contains(out, "refusing to start") {
				t.Fatalf("%s: started, or said nothing:\n%s", name, out)
			}
			for _, s := range []string{dexClientSecret, pw["svc"], adPw["svc"]} {
				if strings.Contains(out, s) {
					t.Fatalf("%s: a secret is in the output", name)
				}
			}
		}
	})

	authn := startService(t, root, authnBin, "19934", append(append([]string{}, base...), "IDENTITY_PROVIDERS_FILE="+providersFile("providers.json", true))...)
	gateway := startService(t, root, gatewayBin, "19935", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	waitUntil(t, 60*time.Second, "the domain controller to answer", func() bool {
		s, _ := ldapLoginAt(t, gateway.baseURL, "samba-ad", "alice", adPw["alice"])
		return s == http.StatusOK
	})

	t.Run("the login screen learns the providers and directories by id and label, nothing else", func(t *testing.T) {
		_, oidcList := getJSON(t, gateway.baseURL+"/auth/oidc")
		_, ldapList := getJSON(t, gateway.baseURL+"/auth/ldap")
		if oidcList != `{"enabled":true,"providers":[{"id":"dex-a","label":"Dex A"},{"id":"dex-b","label":"Dex B"}]}`+"\n" {
			t.Fatalf("GET /auth/oidc: %s", oidcList)
		}
		if ldapList != `{"directories":[{"id":"openldap","label":"OpenLDAP"},{"id":"samba-ad","label":"Active Directory"}],"enabled":true}`+"\n" {
			t.Fatalf("GET /auth/ldap: %s", ldapList)
		}
	})

	var dexA, dexB, openLDAPAlice, adAlice string
	t.Run("four providers at once: each user logs in, with the roles of its own provider's map", func(t *testing.T) {
		for _, c := range []struct {
			name  string
			login func() (int, string)
			into  *string
			want  *regexp.Regexp
			roles string
		}{
			{"Dex A, which adopts the accounts made before", func() (int, string) { return dexLogin(t, gateway.baseURL, "dex-a") }, &dexA, regexp.MustCompile(`^` + regexp.QuoteMeta(legacyName) + `$`), "[platform-admin]"},
			{"Dex B, the same user and the same sub", func() (int, string) { return dexLogin(t, gateway.baseURL, "dex-b") }, &dexB, regexp.MustCompile(`^oidc:dex-b:` + regexp.QuoteMeta(sub) + `$`), "[dba]"},
			{"OpenLDAP's alice", func() (int, string) { return ldapLoginAt(t, gateway.baseURL, "openldap", "alice", pw["alice"]) }, &openLDAPAlice, regexp.MustCompile(`^ldap:openldap:[0-9a-f-]{36}$`), "[platform-admin]"},
			{"Active Directory's alice", func() (int, string) { return ldapLoginAt(t, gateway.baseURL, "samba-ad", "alice", adPw["alice"]) }, &adAlice, regexp.MustCompile(`^ldap:samba-ad:[0-9a-f-]{36}$`), "[vault-admin]"},
		} {
			status, body := c.login()
			if status != http.StatusOK {
				t.Fatalf("%s: %d %s", c.name, status, body)
			}
			name, roles := whoIs(t, authn.baseURL, accessToken(body))
			if !c.want.MatchString(name) || fmt.Sprint(roles) != c.roles {
				t.Fatalf("%s: account %q with %v, want %s with %s", c.name, name, roles, c.want, c.roles)
			}
			*c.into = name
		}
		var ids []string
		for _, name := range []string{dexA, dexB} {
			var id, provider string
			if err := db.QueryRow(`SELECT id, identity_provider FROM users WHERE username = $1`, name).Scan(&id, &provider); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id+"/"+provider)
		}
		if ids[0] == ids[1] || !strings.HasSuffix(ids[0], "/") || !strings.HasSuffix(ids[1], "/dex-b") {
			t.Fatalf("the same sub at two issuers: %v, want two accounts, the first adopted (provider \"\")", ids)
		}
	})

	t.Run("a code of Dex B with a login started at Dex A is refused: exchanged where it was started, it is not known there", func(t *testing.T) {
		_, atA := oidcStartAt(t, gateway.baseURL, "dex-a")
		stateA := mustQuery(t, atA, "state")
		_, atB := oidcStartAt(t, gateway.baseURL, "dex-b")
		codeB, _ := dexCodeFor(t, atB)
		if status, body := oidcCallback(t, gateway.baseURL, codeB, stateA); status != http.StatusUnauthorized {
			t.Fatalf("B's code on A's login: %d %s, want 401", status, body)
		}
	})

	t.Run("no provider named among several, or an unknown one: 400, and no directory is asked", func(t *testing.T) {
		binds := strings.Count(directoryLogs(ldapContainer), " BIND ")
		if binds == 0 {
			t.Fatal("slapd logs no BIND: counting them would prove nothing")
		}
		for _, dir := range []string{"", "nope"} {
			if status, body := ldapLoginAt(t, gateway.baseURL, dir, "alice", pw["alice"]); status != http.StatusBadRequest {
				t.Fatalf("directory %q: %d %s, want 400", dir, status, body)
			}
		}
		for _, p := range []string{"", "nope"} {
			if status, _ := oidcStartAt(t, gateway.baseURL, p); status != http.StatusBadRequest {
				t.Fatalf("provider %q: %d, want 400", p, status)
			}
		}
		time.Sleep(time.Second) // slapd writes its log as it goes
		if after := strings.Count(directoryLogs(ldapContainer), " BIND "); after != binds {
			t.Fatalf("OpenLDAP received %d bind(s) for logins that named no directory", after-binds)
		}
	})

	t.Run("OpenLDAP's password at Active Directory is refused there, and OpenLDAP is not asked", func(t *testing.T) {
		binds := strings.Count(directoryLogs(ldapContainer), " BIND ")
		if status, _ := ldapLoginAt(t, gateway.baseURL, "samba-ad", "alice", pw["alice"]); status != http.StatusUnauthorized {
			t.Fatalf("%d, want 401", status)
		}
		time.Sleep(time.Second)
		if after := strings.Count(directoryLogs(ldapContainer), " BIND "); after != binds {
			t.Fatal("a login at Active Directory asked OpenLDAP")
		}
	})

	t.Run("without adopt_legacy_accounts, the accounts made before are no entry's: said at start, and Dex A's user gets a new account", func(t *testing.T) {
		fresh := startService(t, root, authnBin, "19936", append(append([]string{}, base...), "IDENTITY_PROVIDERS_FILE="+providersFile("no-adopt.json", false))...)
		freshGateway := startService(t, root, gatewayBin, "19937", "AUTHENTICATION_URL="+fresh.baseURL, "CLIENT_LOGIN_BURST=100")
		if !strings.Contains(fresh.out.String(), "made before ADR-0076 belong to no entry of IDENTITY_PROVIDERS_FILE") {
			t.Fatalf("the start does not say the accounts made before are no entry's:\n%s", fresh.out.String())
		}
		status, body := dexLogin(t, freshGateway.baseURL, "dex-a")
		if status != http.StatusOK {
			t.Fatalf("%d %s", status, body)
		}
		if name, _ := whoIs(t, fresh.baseURL, accessToken(body)); name != "oidc:dex-a:"+sub {
			t.Fatalf("account %q, want a new oidc:dex-a:%s — never the one made before", name, sub)
		}
	})

	t.Run("the logs hold no secret", func(t *testing.T) {
		for _, out := range []string{legacy.out.String(), authn.out.String(), gateway.out.String()} {
			for _, s := range []string{dexClientSecret, pw["svc"], adPw["svc"], pw["alice"], adPw["alice"]} {
				if strings.Contains(out, s) {
					t.Fatal("a secret is in a log")
				}
			}
		}
	})
}

func mustQuery(t *testing.T, raw, key string) string {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatal(err)
	}
	return u.Query().Get(key)
}

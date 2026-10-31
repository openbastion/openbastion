package integration_test

// ADR-0061 against two real directories — OpenLDAP (Debian's slapd, StartTLS) and an Active
// Directory (a Samba domain controller, LDAPS) — built from the pinned official Debian image, with
// a certificate this test makes: a directory user logs in through the Gateway with the directory's
// password, and gets the roles of its declared groups only; everything else is refused, and no
// password is ever written.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
)

// writeDirectoryPKI writes, in dir, an authority and the directory's certificate for 127.0.0.1 and
// localhost (ca.pem, cert.pem, key.pem); it returns another authority's file, which signs nothing
// the directory holds.
func writeDirectoryPKI(t *testing.T, dir string) (otherCA string) {
	t.Helper()
	newCA := func(name string) (*x509.Certificate, *ecdsa.PrivateKey, []byte) {
		key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), IsCA: true, BasicConstraintsValid: true,
			KeyUsage: x509.KeyUsageCertSign}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, _ := x509.ParseCertificate(der)
		return cert, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	}
	write := func(name string, b []byte) {
		if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ca, caKey, caPEM := newCA("openbastion-test-directory-ca")
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano() + 1), Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	write("ca.pem", caPEM)
	write("cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	write("key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	_, _, otherPEM := newCA("another-authority")
	other := filepath.Join(t.TempDir(), "other-ca.pem")
	if err := os.WriteFile(other, otherPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	return other
}

// startDirectory builds the image of context (testdata/ldap/<name>), runs it with seed mounted at
// /seed, and returns the container's name and the host address of port.
func startDirectory(t *testing.T, root, name, seed, port string) (container, addr string) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skip("docker not installed — skipping the test against a real directory")
	}
	image := "openbastion-test-" + name
	if out, err := exec.Command("docker", "build", "-q", "-t", image, filepath.Join(root, "test/integration/testdata/ldap", name)).CombinedOutput(); err != nil {
		t.Fatalf("docker build %s: %v\n%s", name, err, out)
	}
	container = fmt.Sprintf("ob-test-%s-%d", name, time.Now().UnixNano())
	if out, err := exec.Command("docker", "run", "-d", "--rm", "--name", container, "-p", "127.0.0.1::"+port, "-v", seed+":/seed:ro", image).CombinedOutput(); err != nil {
		t.Fatalf("docker run %s: %v\n%s", name, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("docker", "rm", "-f", container).Run() })
	out, err := exec.Command("docker", "port", container, port+"/tcp").Output()
	if err != nil {
		t.Fatalf("docker port: %v", err)
	}
	addr = strings.TrimSpace(strings.Split(string(out), "\n")[0])
	return container, addr
}

func directoryLogs(container string) string {
	out, _ := exec.Command("docker", "logs", container).CombinedOutput()
	return string(out)
}

// ldapLogin is POST /auth/ldap/login: the status, and the token if any.
func ldapLogin(t *testing.T, gatewayURL, username, password string) (int, string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"username": username, "password": password})
	resp, err := http.Post(gatewayURL+"/auth/ldap/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		AccessToken string `json:"accessToken"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	return resp.StatusCode, out.AccessToken
}

// whoIs is what the Authentication Service says a token is.
func whoIs(t *testing.T, authnURL, token string) (username string, roles []string) {
	t.Helper()
	body, _ := json.Marshal(map[string]string{"token": token})
	resp, err := http.Post(authnURL+"/auth/v1/verify", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Username string   `json:"username"`
		Roles    []string `json:"roles"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&out)
	sort.Strings(out.Roles)
	return out.Username, out.Roles
}

func writeFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

var uuidPattern = regexp.MustCompile(`^ldap:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

const openLDAPData = `dn: dc=example,dc=test
objectClass: top
objectClass: dcObject
objectClass: organization
o: Example
dc: example

dn: ou=people,dc=example,dc=test
objectClass: organizationalUnit
ou: people

dn: ou=others,dc=example,dc=test
objectClass: organizationalUnit
ou: others

dn: ou=service,dc=example,dc=test
objectClass: organizationalUnit
ou: service

dn: ou=groups,dc=example,dc=test
objectClass: organizationalUnit
ou: groups

dn: cn=svc-bastion,ou=service,dc=example,dc=test
objectClass: organizationalRole
objectClass: simpleSecurityObject
cn: svc-bastion
userPassword: {{svc}}

dn: uid=alice,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: alice
cn: Alice Liddell
sn: Liddell
displayName: Alice L.
userPassword: {{alice}}

dn: uid=bob,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: bob
cn: Bob
sn: B
userPassword: {{bob}}

dn: uid=carol,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: carol
cn: Carol
sn: C
userPassword: {{carol}}

dn: uid=twin,ou=people,dc=example,dc=test
objectClass: inetOrgPerson
uid: twin
cn: Twin One
sn: T
userPassword: {{twin}}

dn: uid=twin,ou=others,dc=example,dc=test
objectClass: inetOrgPerson
uid: twin
cn: Twin Two
sn: T
userPassword: {{twin}}

dn: cn=bastion-admins,ou=groups,dc=example,dc=test
objectClass: groupOfNames
cn: bastion-admins
member: uid=alice,ou=people,dc=example,dc=test

dn: cn=dbas,ou=groups,dc=example,dc=test
objectClass: groupOfUniqueNames
cn: dbas
uniqueMember: uid=bob,ou=people,dc=example,dc=test

dn: cn=unmapped,ou=groups,dc=example,dc=test
objectClass: groupOfNames
cn: unmapped
member: uid=carol,ou=people,dc=example,dc=test
`

func TestLDAPFlow_ADirectoryUserLogsInWithTheDirectorysPassword_RolesFromItsDeclaredGroupsOnly(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-61")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-61")
	pw := map[string]string{"svc": "Svc-Bastion-pass 1", "alice": "Alice-Pass 0123", "bob": "Bob-Pass-0123", "carol": "Carol-Pass-0123", "twin": "Twin-Pass-0123", "admin": "Admin-Pass-0123"}

	seed := t.TempDir()
	otherCA := writeDirectoryPKI(t, seed)
	data := openLDAPData
	for k, v := range pw {
		data = strings.ReplaceAll(data, "{{"+k+"}}", v)
	}
	writeFile(t, seed, "data.ldif", data, 0o644)
	writeFile(t, seed, "admin-password", pw["admin"], 0o644)
	container, addr := startDirectory(t, root, "openldap", seed, "389")
	// The service tries the directory once at its start: the directory is up before it.
	waitUntil(t, 60*time.Second, "slapd to start", func() bool { return strings.Contains(directoryLogs(container), "slapd starting") })

	conf := t.TempDir()
	svcFile := writeFile(t, conf, "bind-password", pw["svc"]+"\n", 0o600)
	roleMap := writeFile(t, conf, "roles.json", `{"cn=bastion-admins,ou=groups,dc=example,dc=test": ["platform-admin"], "CN=DBAs, OU=Groups, DC=Example, DC=Test": ["dba"]}`, 0o600)
	ldapEnv := func(extra ...string) []string {
		return append([]string{"SKIP_DEMO_SEED=1", "LDAP_URL=ldap://" + addr, "LDAP_CA_FILE=" + filepath.Join(seed, "ca.pem"), "LDAP_SCHEMA=rfc",
			"LDAP_BIND_DN=cn=svc-bastion,ou=service,dc=example,dc=test", "LDAP_BIND_PASSWORD_FILE=" + svcFile,
			"LDAP_USER_BASE_DN=dc=example,dc=test", "LDAP_GROUP_BASE_DN=ou=groups,dc=example,dc=test", "LDAP_ROLE_MAP_FILE=" + roleMap}, extra...)
	}

	t.Run("LDAP is all or nothing, its map must name groups, and nothing goes in clear", func(t *testing.T) {
		for name, env := range map[string][]string{
			"half configured":          {"LDAP_URL=ldaps://127.0.0.1:1"},
			"the authority alone":      {"LDAP_CA_FILE=" + otherCA},
			"a scheme that is not TLS": append(ldapEnv(), "LDAP_URL=http://"+addr),
			"a map of names, not DNs":  append(ldapEnv(), "LDAP_ROLE_MAP_FILE="+writeFile(t, conf, "names.json", `{"bastion-admins": ["platform-admin"]}`, 0o600)),
			"a password others read":   append(ldapEnv(), "LDAP_BIND_PASSWORD_FILE="+writeFile(t, conf, "open-pw", pw["svc"], 0o644)),
			"a schema not known":       append(ldapEnv(), "LDAP_SCHEMA=custom"),
		} {
			out := runUntilExit(t, root, authnBin, append([]string{"PORT=19613"}, env...)...)
			if !strings.Contains(out, "LDAP") {
				t.Fatalf("%s: the refusal does not name LDAP:\n%s", name, out)
			}
			if strings.Contains(out, pw["svc"]) {
				t.Fatalf("%s: the service account's password is in the output", name)
			}
		}
	})

	authn := startService(t, root, authnBin, "19611", ldapEnv()...)
	gateway := startService(t, root, gatewayBin, "19612", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	waitUntil(t, 30*time.Second, "the directory to answer", func() bool {
		s, _ := ldapLogin(t, gateway.baseURL, "alice", pw["alice"])
		return s == http.StatusOK
	})

	t.Run("the Gateway says directory login is on", func(t *testing.T) {
		resp, err := http.Get(gateway.baseURL + "/auth/ldap")
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		var out struct {
			Enabled bool `json:"enabled"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&out)
		if resp.StatusCode != http.StatusOK || !out.Enabled {
			t.Fatalf("GET /auth/ldap: %d %+v", resp.StatusCode, out)
		}
	})

	var aliceAccount string
	t.Run("a user logs in with the directory's password, as ldap:<entryUUID>, with its groups' roles only", func(t *testing.T) {
		for _, c := range []struct{ user, roles string }{{"alice", "[platform-admin]"}, {"bob", "[dba]"}} {
			status, token := ldapLogin(t, gateway.baseURL, c.user, pw[c.user])
			if status != http.StatusOK || token == "" {
				t.Fatalf("%s: %d", c.user, status)
			}
			username, roles := whoIs(t, authn.baseURL, token)
			if !uuidPattern.MatchString(username) || fmt.Sprint(roles) != c.roles {
				t.Fatalf("%s: account %q roles %v, want ldap:<entryUUID> with %s", c.user, username, roles, c.roles)
			}
			if c.user == "alice" {
				aliceAccount = username
			}
		}
		// The directory account is not a local one: neither its login name nor its account name
		// logs in at /auth/login with the directory's password.
		for _, name := range []string{"alice", aliceAccount} {
			body, _ := json.Marshal(map[string]string{"username": name, "password": pw["alice"]})
			resp, err := http.Post(gateway.baseURL+"/auth/login", "application/json", bytes.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusUnauthorized {
				t.Fatalf("a local login as %q with the directory password: %d", name, resp.StatusCode)
			}
		}
	})

	t.Run("what the directory does not vouch for is refused, the same way", func(t *testing.T) {
		for name, c := range map[string][2]string{
			"a wrong password":              {"alice", "not-her-password"},
			"an empty password (anonymous)": {"alice", ""},
			"an unknown user":               {"mallory", pw["alice"]},
			"a wildcard, escaped":           {"alic*", pw["alice"]},
			"a filter injection, escaped":   {"alice)(uid=*", pw["alice"]},
			"a name two entries answer to":  {"twin", pw["twin"]},
			"another user's password":       {"bob", pw["alice"]},
		} {
			if status, token := ldapLogin(t, gateway.baseURL, c[0], c[1]); status != http.StatusUnauthorized || token != "" {
				t.Fatalf("%s: %d, want 401", name, status)
			}
		}
	})

	t.Run("the directory login takes from the per-address login budget", func(t *testing.T) {
		tight := startService(t, root, gatewayBin, "19618", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=2")
		var codes []int
		for i := 0; i < 3; i++ {
			status, _ := ldapLogin(t, tight.baseURL, "alice", "not-her-password")
			codes = append(codes, status)
		}
		if fmt.Sprint(codes) != "[401 401 429]" {
			t.Fatalf("three logins with a budget of two: %v", codes)
		}
	})

	t.Run("a user whose groups give no role is refused with 403", func(t *testing.T) {
		if status, _ := ldapLogin(t, gateway.baseURL, "carol", pw["carol"]); status != http.StatusForbidden {
			t.Fatalf("carol: %d, want 403", status)
		}
	})

	t.Run("an authority that did not sign the directory, a refused service account, a directory down: 503, never a login", func(t *testing.T) {
		wrongCA := startService(t, root, authnBin, "19614", ldapEnv("LDAP_CA_FILE="+otherCA)...)
		badSvc := startService(t, root, authnBin, "19615", ldapEnv("LDAP_BIND_PASSWORD_FILE="+writeFile(t, conf, "bad-pw", "not-the-password", 0o600))...)
		for name, a := range map[string]*runningService{"another authority": wrongCA, "a refused service account": badSvc} {
			gw := startService(t, root, gatewayBin, map[string]string{"another authority": "19616", "a refused service account": "19617"}[name], "AUTHENTICATION_URL="+a.baseURL)
			if status, token := ldapLogin(t, gw.baseURL, "alice", pw["alice"]); status != http.StatusServiceUnavailable || token != "" {
				t.Fatalf("%s: %d, want 503", name, status)
			}
			if !strings.Contains(a.out.String(), "the directory does not answer now") {
				t.Fatalf("%s: the start does not say the directory does not answer:\n%s", name, a.out.String())
			}
		}
		if out, err := exec.Command("docker", "pause", container).CombinedOutput(); err != nil {
			t.Fatalf("docker pause: %v %s", err, out)
		}
		status, _ := ldapLogin(t, gateway.baseURL, "alice", pw["alice"])
		_ = exec.Command("docker", "unpause", container).Run()
		if status != http.StatusServiceUnavailable {
			t.Fatalf("the directory paused: %d, want 503", status)
		}
	})

	t.Run("the directory saw TLS only, and no password is in any log", func(t *testing.T) {
		for name, out := range map[string]string{"authentication": authn.out.String(), "gateway": gateway.out.String()} {
			for k, v := range pw {
				if strings.Contains(out, v) {
					t.Fatalf("the %s log holds %s's password", name, k)
				}
			}
		}
		if !strings.Contains(authn.out.String(), "directory login (LDAP, schema rfc) with ldap://"+addr+" over TLS") {
			t.Fatalf("the start does not say directory login is on over TLS:\n%s", authn.out.String())
		}
	})
}

func TestLDAPFlow_AnActiveDirectoryUserLogsIn_NestedGroupsCount_ADisabledAccountIsRefused(t *testing.T) {
	root := repoRoot(t)
	authnBin := buildBinary(t, root, "./services/access/authentication/cmd/authentication", "authentication-61ad")
	gatewayBin := buildBinary(t, root, "./services/access/api-gateway/cmd/api-gateway", "api-gateway-61ad")
	pw := map[string]string{"admin": "Adm1n-Pass-0123!", "svc": "Svc-Bastion-0123!", "alice": "Alice-Pass-0123!", "dave": "Dave-Pass-0123!", "carol": "Carol-Pass-0123!"}

	seed := t.TempDir()
	writeDirectoryPKI(t, seed)
	writeFile(t, seed, "admin-password", pw["admin"], 0o644)
	// alice is in bastion-ops, which is in bastion-admins: the role comes through the nesting.
	// dave is in bastion-admins directly, and disabled. carol is in no group.
	writeFile(t, seed, "setup.sh", fmt.Sprintf(`set -e
samba-tool user create svc-bastion '%s' >/dev/null
samba-tool user create alice '%s' --given-name=Alice --surname=Liddell >/dev/null
samba-tool user create dave '%s' >/dev/null
samba-tool user create carol '%s' >/dev/null
samba-tool group add bastion-admins >/dev/null
samba-tool group add bastion-ops >/dev/null
samba-tool group addmembers bastion-admins bastion-ops,dave >/dev/null
samba-tool group addmembers bastion-ops alice >/dev/null
samba-tool user disable dave >/dev/null
`, pw["svc"], pw["alice"], pw["dave"], pw["carol"]), 0o644)
	container, addr := startDirectory(t, root, "samba", seed, "636")
	waitUntil(t, 180*time.Second, "the domain controller to be provisioned", func() bool {
		return strings.Contains(directoryLogs(container), "samba: ready to start")
	})

	conf := t.TempDir()
	authn := startService(t, root, authnBin, "19621", "SKIP_DEMO_SEED=1", "LDAP_URL=ldaps://"+addr, "LDAP_CA_FILE="+filepath.Join(seed, "ca.pem"), "LDAP_SCHEMA=ad",
		"LDAP_BIND_DN=CN=svc-bastion,CN=Users,DC=example,DC=test", "LDAP_BIND_PASSWORD_FILE="+writeFile(t, conf, "bind-password", pw["svc"], 0o600),
		"LDAP_USER_BASE_DN=CN=Users,DC=example,DC=test", "LDAP_GROUP_BASE_DN=DC=example,DC=test",
		"LDAP_ROLE_MAP_FILE="+writeFile(t, conf, "roles.json", `{"CN=bastion-admins,CN=Users,DC=example,DC=test": ["platform-admin"]}`, 0o600))
	gateway := startService(t, root, gatewayBin, "19622", "AUTHENTICATION_URL="+authn.baseURL, "CLIENT_LOGIN_BURST=100")
	waitUntil(t, 60*time.Second, "the domain controller to answer", func() bool {
		s, _ := ldapLogin(t, gateway.baseURL, "alice", pw["alice"])
		return s == http.StatusOK
	})

	t.Run("an AD user logs in by sAMAccountName, as ldap:<objectGUID>, with the role of a group it is in through another", func(t *testing.T) {
		status, token := ldapLogin(t, gateway.baseURL, "alice", pw["alice"])
		if status != http.StatusOK {
			t.Fatalf("alice: %d", status)
		}
		username, roles := whoIs(t, authn.baseURL, token)
		if !uuidPattern.MatchString(username) || fmt.Sprint(roles) != "[platform-admin]" {
			t.Fatalf("alice: account %q roles %v, want ldap:<objectGUID> with [platform-admin] through bastion-ops", username, roles)
		}
		// The GUID is the one AD shows (its first three groups are stored little-endian).
		out, err := exec.Command("docker", "exec", container, "samba-tool", "user", "show", "alice", "--attributes=objectGUID").CombinedOutput()
		if err != nil {
			t.Fatalf("samba-tool user show: %v %s", err, out)
		}
		guid := regexp.MustCompile(`objectGUID: ([0-9a-f-]{36})`).FindStringSubmatch(string(out))
		if guid == nil || username != "ldap:"+guid[1] {
			t.Fatalf("account %q, but AD says %q", username, out)
		}
	})

	t.Run("a disabled account, a wrong password, an empty one, a user with no group: refused", func(t *testing.T) {
		for name, c := range map[string]struct {
			user, password string
			want           int
		}{
			"a disabled account in the admins": {"dave", pw["dave"], http.StatusUnauthorized},
			"a wrong password":                 {"alice", "Not-Her-Pass-0123!", http.StatusUnauthorized},
			"an empty password (anonymous)":    {"alice", "", http.StatusUnauthorized},
			"a wildcard, escaped":              {"alic*", pw["alice"], http.StatusUnauthorized},
			"a user in no group":               {"carol", pw["carol"], http.StatusForbidden},
		} {
			if status, token := ldapLogin(t, gateway.baseURL, c.user, c.password); status != c.want || token != "" {
				t.Fatalf("%s: %d, want %d", name, status, c.want)
			}
		}
	})

	t.Run("no password is in any log", func(t *testing.T) {
		for name, out := range map[string]string{"authentication": authn.out.String(), "gateway": gateway.out.String()} {
			for k, v := range pw {
				if strings.Contains(out, v) {
					t.Fatalf("the %s log holds %s's password", name, k)
				}
			}
		}
	})
}

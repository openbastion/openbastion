package infrastructure_test

import (
	"bytes"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

const bindSecret = "service-Acc0unt pass"

func secretFile(t *testing.T, value string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(p, []byte(value+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func ldapConfig(t *testing.T) infrastructure.LDAPConfig {
	return infrastructure.LDAPConfig{URL: "ldaps://dc.example.test:636", Schema: "ad", BindDN: "cn=svc-bastion,ou=service,dc=example,dc=test",
		BindPasswordFile: secretFile(t, bindSecret, 0o600), UserBaseDN: "ou=people,dc=example,dc=test", GroupBaseDN: "ou=groups,dc=example,dc=test"}
}

func TestNewLDAPDirectory_RefusesWhatWouldSendAPasswordInClearOrCannotBeRight(t *testing.T) {
	if _, err := infrastructure.NewLDAPDirectory(ldapConfig(t)); err != nil {
		t.Fatalf("a whole configuration: %v", err)
	}
	ok := func(c infrastructure.LDAPConfig) error { _, err := infrastructure.NewLDAPDirectory(c); return err }
	starttls := ldapConfig(t)
	starttls.URL, starttls.Schema = "ldap://127.0.0.1:389", "rfc"
	if err := ok(starttls); err != nil {
		t.Fatalf("ldap:// (StartTLS, even on loopback) with the rfc schema: %v", err)
	}
	cases := map[string]struct {
		edit func(*infrastructure.LDAPConfig)
		says string
	}{
		"a scheme that is not LDAP":     {func(c *infrastructure.LDAPConfig) { c.URL = "https://dc.example.test" }, "LDAP_URL"},
		"credentials in the URL":        {func(c *infrastructure.LDAPConfig) { c.URL = "ldaps://svc:pw@dc.example.test" }, "LDAP_URL"},
		"a DN in the URL":               {func(c *infrastructure.LDAPConfig) { c.URL = "ldaps://dc.example.test/dc=example,dc=test" }, "LDAP_URL"},
		"a query in the URL":            {func(c *infrastructure.LDAPConfig) { c.URL = "ldaps://dc.example.test/?uid" }, "LDAP_URL"},
		"no host":                       {func(c *infrastructure.LDAPConfig) { c.URL = "ldaps:///" }, "LDAP_URL"},
		"a schema that is not known":    {func(c *infrastructure.LDAPConfig) { c.Schema = "custom" }, "LDAP_SCHEMA"},
		"a bind DN that is not a DN":    {func(c *infrastructure.LDAPConfig) { c.BindDN = "svc-bastion" }, "LDAP_BIND_DN"},
		"a user base that is not a DN":  {func(c *infrastructure.LDAPConfig) { c.UserBaseDN = "" }, "LDAP_USER_BASE_DN"},
		"a group base that is not a DN": {func(c *infrastructure.LDAPConfig) { c.GroupBaseDN = "people" }, "LDAP_GROUP_BASE_DN"},
		"a password others can read":    {func(c *infrastructure.LDAPConfig) { c.BindPasswordFile = secretFile(t, bindSecret, 0o644) }, "LDAP_BIND_PASSWORD_FILE is readable"},
		"a password file missing":       {func(c *infrastructure.LDAPConfig) { c.BindPasswordFile = "/nonexistent/pw" }, "LDAP_BIND_PASSWORD_FILE cannot be read"},
		"an empty password file":        {func(c *infrastructure.LDAPConfig) { c.BindPasswordFile = secretFile(t, "", 0o600) }, "one value on one line"},
		"two lines in the password":     {func(c *infrastructure.LDAPConfig) { c.BindPasswordFile = secretFile(t, bindSecret+"\nsecond", 0o600) }, "one value on one line"},
		"an authority file missing":     {func(c *infrastructure.LDAPConfig) { c.CAFile = "/nonexistent/ca.pem" }, "LDAP_CA_FILE"},
		"an authority that is not PEM":  {func(c *infrastructure.LDAPConfig) { c.CAFile = secretFile(t, "not a certificate", 0o600) }, "LDAP_CA_FILE"},
	}
	for name, c := range cases {
		cfg := ldapConfig(t)
		c.edit(&cfg)
		err := ok(cfg)
		if err == nil || !strings.Contains(err.Error(), c.says) {
			t.Fatalf("%s: %v, want a refusal naming %s", name, err, c.says)
		}
		if strings.Contains(err.Error(), bindSecret) {
			t.Fatalf("%s: the refusal holds the service account's password", name)
		}
	}
}

func TestNormalizeRoleMap_GroupsAreComparedAsDNs_AndAKeyThatIsNotOneIsRefused(t *testing.T) {
	m, err := infrastructure.NormalizeRoleMap(application.RoleMap{"CN=Bastion Admins, OU=Groups,DC=Example,DC=Test": {"platform-admin"}})
	if err != nil {
		t.Fatal(err)
	}
	// What the directory returns, in its own spelling, finds the same roles.
	k, err := infrastructure.NormalizeDN("cn=bastion admins,ou=groups,dc=example,dc=test")
	if err != nil || len(m.Roles([]string{k})) != 1 {
		t.Fatalf("the same group in another case and spacing: %q %v → %v", k, err, m.Roles([]string{k}))
	}
	other, _ := infrastructure.NormalizeDN("cn=bastion admins,ou=other,dc=example,dc=test")
	if len(m.Roles([]string{other})) != 0 {
		t.Fatal("a group of the same name elsewhere in the tree gets the roles")
	}
	for name, bad := range map[string]application.RoleMap{
		"a name, not a DN":     {"bastion-admins": {"platform-admin"}},
		"the same group twice": {"cn=a,dc=example,dc=test": {"dba"}, "CN=A,DC=example,DC=test": {"platform-admin"}},
	} {
		if _, err := infrastructure.NormalizeRoleMap(bad); err == nil {
			t.Fatalf("%s: accepted", name)
		}
	}
}

// ldap:// is upgraded by StartTLS before anything else: the first message a directory receives is
// the StartTLS request (OID 1.3.6.1.4.1.1466.20037), never a bind with a password — whatever the
// directory would accept.
func TestLDAPDirectory_OverLDAPTheFirstMessageIsStartTLS_NeverAPasswordInClear(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer c.Close()
		_ = c.SetReadDeadline(time.Now().Add(3 * time.Second))
		buf := make([]byte, 1024)
		n, _ := c.Read(buf)
		got <- buf[:n] // then the connection closes: StartTLS fails, nothing else is sent
	}()
	cfg := ldapConfig(t)
	cfg.URL = "ldap://" + ln.Addr().String()
	d, err := infrastructure.NewLDAPDirectory(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Probe(context.Background()); err == nil {
		t.Fatal("the probe succeeded against a server that answers nothing")
	}
	first := <-got
	if !bytes.Contains(first, []byte("1.3.6.1.4.1.1466.20037")) {
		t.Fatalf("the first message is not a StartTLS request: %q", first)
	}
	if bytes.Contains(first, []byte(bindSecret)) || bytes.Contains(first, []byte("svc-bastion")) {
		t.Fatalf("a bind went out in clear: %q", first)
	}
}

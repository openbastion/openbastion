package infrastructure_test

// IDENTITY_PROVIDERS_FILE (ADR-0076): checked whole; one entry wrong, and nothing is turned on.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

const validProviders = `{
  "oidc": [
    {"id": "dex", "label": "Dex", "issuer": "https://dex.example/dex", "client_id": "ob", "client_secret_file": "/s", "redirect_url": "https://ob.example/ui/", "role_map_file": "/r"},
    {"id": "partner", "label": "Partenaire", "issuer": "https://idp.partner.example", "client_id": "ob", "client_secret_file": "/s", "redirect_url": "https://ob.example/ui/", "role_map_file": "/r", "adopt_legacy_accounts": true}
  ],
  "directories": [
    {"id": "corp-ad", "label": "Active Directory", "url": "ldaps://dc.example:636", "schema": "ad", "bind_dn": "CN=svc,DC=example,DC=com", "bind_password_file": "/p", "user_base_dn": "CN=Users,DC=example,DC=com", "group_base_dn": "DC=example,DC=com", "role_map_file": "/r"},
    {"id": "openldap", "label": "OpenLDAP", "url": "ldap://ldap.example:389", "schema": "rfc", "bind_dn": "cn=svc,dc=example,dc=org", "bind_password_file": "/p", "user_base_dn": "ou=people,dc=example,dc=org", "group_base_dn": "ou=groups,dc=example,dc=org", "role_map_file": "/r"}
  ]
}`

func writeProviders(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "providers.json")
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProvidersFile_AValidFileIsReadWhole(t *testing.T) {
	f, err := infrastructure.LoadProvidersFile(writeProviders(t, validProviders, 0o644))
	if err != nil {
		t.Fatal(err)
	}
	if len(f.OIDC) != 2 || len(f.Directories) != 2 || !f.OIDC[1].AdoptLegacyAccounts || f.Directories[0].Schema != "ad" {
		t.Fatalf("%+v", f)
	}
}

func TestProvidersFile_EachMistakeStopsTheWholeFile(t *testing.T) {
	entry := `{"id": "dex", "label": "Dex", "issuer": "https://dex.example/dex", "client_id": "ob", "client_secret_file": "/s", "redirect_url": "https://ob.example/ui/", "role_map_file": "/r"}`
	dir := `{"id": "ad", "label": "AD", "url": "ldaps://dc.example:636", "schema": "ad", "bind_dn": "CN=svc,DC=example,DC=com", "bind_password_file": "/p", "user_base_dn": "CN=Users,DC=example,DC=com", "group_base_dn": "DC=example,DC=com", "role_map_file": "/r"}`
	with := func(oidc, dirs []string) string {
		return `{"oidc": [` + strings.Join(oidc, ",") + `], "directories": [` + strings.Join(dirs, ",") + `]}`
	}
	many := make([]string, 17)
	for i := range many {
		many[i] = strings.Replace(strings.Replace(entry, `"dex"`, `"p`+string(rune('a'+i))+`"`, 1), "dex.example", "idp"+string(rune('a'+i))+".example", 1)
	}
	for name, c := range map[string]struct{ content, want string }{
		"nothing declared":             {`{"oidc": [], "directories": []}`, "declares no provider"},
		"an unknown field":             {`{"oidc": [], "directories": [], "saml": []}`, "unknown field"},
		"two objects":                  {`{"oidc": [` + entry + `]} {}`, "more than one JSON object"},
		"more than 16":                 {with(many, nil), "at most 16"},
		"an id with a colon":           {with([]string{strings.Replace(entry, `"dex"`, `"de:x"`, 1)}, nil), "the id is 1 to 32"},
		"an id in capitals":            {with([]string{strings.Replace(entry, `"dex"`, `"Dex"`, 1)}, nil), "the id is 1 to 32"},
		"an empty id":                  {with([]string{strings.Replace(entry, `"id": "dex"`, `"id": ""`, 1)}, nil), "the id is 1 to 32"},
		"the same id, oidc and ldap":   {with([]string{entry}, []string{strings.Replace(dir, `"ad"`, `"dex"`, 1)}), "declared twice"},
		"a label with a control":       {with([]string{strings.Replace(entry, `"label": "Dex"`, `"label": "D\u0007x"`, 1)}, nil), "the label"},
		"no label":                     {with([]string{strings.Replace(entry, `"label": "Dex"`, `"label": ""`, 1)}, nil), "the label"},
		"no client secret file":        {with([]string{strings.Replace(entry, `"client_secret_file": "/s"`, `"client_secret_file": ""`, 1)}, nil), "client_secret_file is required"},
		"no role map":                  {with(nil, []string{strings.Replace(dir, `"role_map_file": "/r"`, `"role_map_file": ""`, 1)}), "role_map_file is required"},
		"the same issuer twice":        {with([]string{entry, strings.Replace(entry, `"dex"`, `"dex2"`, 1)}, nil), "the same issuer"},
		"the same directory and base":  {with(nil, []string{dir, strings.Replace(strings.Replace(dir, `"ad"`, `"ad2"`, 1), "dc.example", "DC.EXAMPLE", 1)}), "the same directory and base"},
		"two oidc entries adopt":       {with([]string{strings.Replace(entry, `"role_map_file": "/r"`, `"role_map_file": "/r", "adopt_legacy_accounts": true`, 1), strings.Replace(strings.Replace(strings.Replace(entry, `"dex"`, `"dex2"`, 1), "dex.example", "dex2.example", 1), `"role_map_file": "/r"`, `"role_map_file": "/r", "adopt_legacy_accounts": true`, 1)}, nil), "at most one oidc entry adopts"},
		"two directories adopt":        {with(nil, []string{strings.Replace(dir, `"role_map_file": "/r"`, `"role_map_file": "/r", "adopt_legacy_accounts": true`, 1), strings.Replace(strings.Replace(strings.Replace(dir, `"ad"`, `"ad2"`, 1), "dc.example", "dc2.example", 1), `"role_map_file": "/r"`, `"role_map_file": "/r", "adopt_legacy_accounts": true`, 1)}), "at most one directory adopts"},
		"a user base that is not a DN": {with(nil, []string{strings.Replace(dir, `"user_base_dn": "CN=Users,DC=example,DC=com"`, `"user_base_dn": "not a dn"`, 1)}), "user_base_dn is not a DN"},
	} {
		_, err := infrastructure.LoadProvidersFile(writeProviders(t, c.content, 0o600))
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want an error saying %q", name, err, c.want)
		}
	}
}

func TestProvidersFile_AFileOthersCanWriteIsRefused(t *testing.T) {
	for _, mode := range []os.FileMode{0o664, 0o646, 0o666} {
		if _, err := infrastructure.LoadProvidersFile(writeProviders(t, validProviders, mode)); err == nil || !strings.Contains(err.Error(), "writable") {
			t.Fatalf("mode %#o: %v", mode, err)
		}
	}
	if _, err := infrastructure.LoadProvidersFile(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Fatal("an absent file was read")
	}
}

func TestProvidersFile_AClientSecretIsReadFromAFileItsOwnerAloneReads(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "secret")
	_ = os.WriteFile(p, []byte("s3cret-value\n"), 0o600)
	v, err := infrastructure.ReadClientSecret(infrastructure.OIDCEntryConfig{ID: "dex", ClientSecretFile: p})
	if err != nil || v != "s3cret-value" {
		t.Fatalf("%q %v", v, err)
	}
	_ = os.Chmod(p, 0o640)
	if _, err := infrastructure.ReadClientSecret(infrastructure.OIDCEntryConfig{ID: "dex", ClientSecretFile: p}); err == nil || strings.Contains(err.Error(), "s3cret") {
		t.Fatalf("a secret others read: %v", err)
	}
}

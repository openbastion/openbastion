package infrastructure

// IDENTITY_PROVIDERS_FILE (ADR-0076): several OIDC providers and directories at once. The file is
// checked whole before anything is turned on — one entry wrong, and the service does not start.
// It holds no secret: client_secret_file and bind_password_file name files only their owner reads.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"unicode"
)

// MaxIdentityProviders bounds the entries of the file, OIDC and directories together.
const MaxIdentityProviders = 16

// ProvidersFile is IDENTITY_PROVIDERS_FILE, checked.
type ProvidersFile struct {
	OIDC        []OIDCEntryConfig      `json:"oidc"`
	Directories []DirectoryEntryConfig `json:"directories"`
}

// OIDCEntryConfig is one OIDC provider: the fields of ADR-0035, its ID, label and role map.
type OIDCEntryConfig struct {
	ID                  string `json:"id"`
	Label               string `json:"label"`
	Issuer              string `json:"issuer"`
	ClientID            string `json:"client_id"`
	ClientSecretFile    string `json:"client_secret_file"`
	RedirectURL         string `json:"redirect_url"`
	RoleMapFile         string `json:"role_map_file"`
	GroupsClaim         string `json:"groups_claim"`
	AdoptLegacyAccounts bool   `json:"adopt_legacy_accounts"`
	// PreviousIssuer declares a change of issuer (ADR-0078): the one this id was bound to.
	PreviousIssuer string `json:"previous_issuer"`
}

// DirectoryEntryConfig is one directory: the fields of ADR-0061, its ID, label and role map.
type DirectoryEntryConfig struct {
	ID                  string `json:"id"`
	Label               string `json:"label"`
	URL                 string `json:"url"`
	CAFile              string `json:"ca_file"`
	Schema              string `json:"schema"`
	BindDN              string `json:"bind_dn"`
	BindPasswordFile    string `json:"bind_password_file"`
	UserBaseDN          string `json:"user_base_dn"`
	GroupBaseDN         string `json:"group_base_dn"`
	RoleMapFile         string `json:"role_map_file"`
	AdoptLegacyAccounts bool   `json:"adopt_legacy_accounts"`
}

// LoadProvidersFile reads and checks the file. Its errors name the entry and the field, never what
// a secret file holds. What it does not check, the constructors do (NewOIDCProvider,
// NewLDAPDirectory, LoadRoleMap) before the service starts.
func LoadProvidersFile(path string) (*ProvidersFile, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("IDENTITY_PROVIDERS_FILE cannot be read: %v", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("IDENTITY_PROVIDERS_FILE must be a regular file")
	}
	// Whoever can write it can declare a provider whose groups are platform-admin.
	if info.Mode().Perm()&0o022 != 0 {
		return nil, fmt.Errorf("IDENTITY_PROVIDERS_FILE is writable by its group or by others (mode %#o): make it 0644 or stricter", info.Mode().Perm())
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("IDENTITY_PROVIDERS_FILE cannot be read: %v", err)
	}
	var f ProvidersFile
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("IDENTITY_PROVIDERS_FILE is not a providers file: %v", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("IDENTITY_PROVIDERS_FILE holds more than one JSON object")
	}
	return &f, f.check()
}

func (f *ProvidersFile) check() error {
	n := len(f.OIDC) + len(f.Directories)
	if n == 0 {
		return errors.New("IDENTITY_PROVIDERS_FILE declares no provider: remove the variable to turn federation off")
	}
	if n > MaxIdentityProviders {
		return fmt.Errorf("IDENTITY_PROVIDERS_FILE declares %d providers, at most %d", n, MaxIdentityProviders)
	}
	ids := map[string]bool{}
	checkID := func(kind, id, label string) error {
		if !providerID(id) {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: %s %q: the id is 1 to 32 characters of a-z, 0-9 and -", kind, id)
		}
		if ids[id] {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: the id %q is declared twice: it is what binds the accounts to their provider", id)
		}
		ids[id] = true
		if !providerLabel(label) {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: %s %q: the label is 1 to 64 printable characters", kind, id)
		}
		return nil
	}
	issuers, adopted := map[string]string{}, 0
	for _, e := range f.OIDC {
		if err := checkID("oidc", e.ID, e.Label); err != nil {
			return err
		}
		for field, v := range map[string]string{"issuer": e.Issuer, "client_id": e.ClientID, "client_secret_file": e.ClientSecretFile, "redirect_url": e.RedirectURL, "role_map_file": e.RoleMapFile} {
			if v == "" {
				return fmt.Errorf("IDENTITY_PROVIDERS_FILE: oidc %q: %s is required", e.ID, field)
			}
		}
		// The same issuer twice would be the same subjects under two IDs: two accounts per person.
		if other, ok := issuers[e.Issuer]; ok {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: oidc %q and %q have the same issuer", other, e.ID)
		}
		issuers[e.Issuer] = e.ID
		if e.AdoptLegacyAccounts {
			adopted++
		}
	}
	if adopted > 1 {
		return errors.New("IDENTITY_PROVIDERS_FILE: at most one oidc entry adopts the accounts made before (adopt_legacy_accounts)")
	}
	dirs, adopted := map[string]string{}, 0
	for _, e := range f.Directories {
		if err := checkID("directory", e.ID, e.Label); err != nil {
			return err
		}
		for field, v := range map[string]string{"url": e.URL, "schema": e.Schema, "bind_dn": e.BindDN, "bind_password_file": e.BindPasswordFile, "user_base_dn": e.UserBaseDN, "group_base_dn": e.GroupBaseDN, "role_map_file": e.RoleMapFile} {
			if v == "" {
				return fmt.Errorf("IDENTITY_PROVIDERS_FILE: directory %q: %s is required", e.ID, field)
			}
		}
		key, err := directoryKey(e.URL, e.UserBaseDN)
		if err != nil {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: directory %q: %v", e.ID, err)
		}
		if other, ok := dirs[key]; ok {
			return fmt.Errorf("IDENTITY_PROVIDERS_FILE: directories %q and %q are the same directory and base", other, e.ID)
		}
		dirs[key] = e.ID
		if e.AdoptLegacyAccounts {
			adopted++
		}
	}
	if adopted > 1 {
		return errors.New("IDENTITY_PROVIDERS_FILE: at most one directory adopts the accounts made before (adopt_legacy_accounts)")
	}
	return nil
}

// directoryKey is what makes two entries the same directory: its host, without case, and its user
// base, normalized.
func directoryKey(rawURL, userBase string) (string, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return "", errors.New("url must be a URL such as ldaps://dc.example:636")
	}
	base, err := NormalizeDN(userBase)
	if err != nil {
		return "", errors.New("user_base_dn is not a DN")
	}
	return strings.ToLower(u.Host) + "|" + base, nil
}

// providerID: 1 to 32 characters of a-z, 0-9 and -.
func providerID(id string) bool {
	if id == "" || len(id) > 32 {
		return false
	}
	for _, c := range id {
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// providerLabel: 1 to 64 printable characters, shown on the login screen.
func providerLabel(l string) bool {
	if l == "" || len([]rune(l)) > 64 {
		return false
	}
	for _, c := range l {
		if !unicode.IsPrint(c) {
			return false
		}
	}
	return true
}

// ReadClientSecret reads an OIDC entry's client secret from its file, readable by its owner only.
func ReadClientSecret(e OIDCEntryConfig) (string, error) {
	return readSecretFile(fmt.Sprintf("IDENTITY_PROVIDERS_FILE: oidc %q: client_secret_file", e.ID), e.ClientSecretFile)
}

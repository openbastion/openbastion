package infrastructure

// The directory adapter of ADR-0061, on github.com/go-ldap/ldap/v3: a service account finds the
// user, a fresh connection binds as the user (the directory checks the password), the service
// account finds the user's groups. Always over TLS; nothing it is given is ever written.

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/go-ldap/ldap/v3"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
)

// LDAPTimeout bounds one directory operation, connection included.
const LDAPTimeout = 5 * time.Second

// The two schemas of ADR-0061: fixed attributes, no free filter.
const (
	SchemaAD  = "ad"
	SchemaRFC = "rfc"
)

// LDAPConfig names a directory and how to search it.
type LDAPConfig struct {
	URL              string // ldaps://host:636, or ldap://host:389 (StartTLS, always)
	CAFile           string // optional: the authority of the directory's certificate
	Schema           string // SchemaAD or SchemaRFC
	BindDN           string // the service account, which searches (read only)
	BindPasswordFile string // its password, readable by its owner only, read at each login
	UserBaseDN       string
	GroupBaseDN      string
}

// A disabled account is not checked here: the directory refuses its bind (measured against Samba AD,
// ADR-0061) — a check of our own could not be shown to change anything.
type schema struct {
	userFilter  string // %s is the login name, escaped
	groupFilter string // %s is the user's DN, escaped
	idAttribute string
	nameAttrs   []string
}

var schemas = map[string]schema{
	SchemaAD: {
		userFilter: "(&(objectCategory=person)(objectClass=user)(sAMAccountName=%s))",
		// LDAP_MATCHING_RULE_IN_CHAIN: the groups the user is in, directly or through other groups.
		groupFilter: "(&(objectClass=group)(member:1.2.840.113556.1.4.1941:=%s))",
		idAttribute: "objectGUID", nameAttrs: []string{"displayName", "cn"},
	},
	SchemaRFC: {
		userFilter:  "(&(objectClass=inetOrgPerson)(uid=%s))",
		groupFilter: "(|(&(objectClass=groupOfNames)(member=%[1]s))(&(objectClass=groupOfUniqueNames)(uniqueMember=%[1]s)))",
		idAttribute: "entryUUID", nameAttrs: []string{"displayName", "cn"},
	},
}

// LDAPDirectory is an application.Directory.
type LDAPDirectory struct {
	cfg      LDAPConfig
	schema   schema
	addr     string // the URL, as dialled
	startTLS bool
	tls      *tls.Config
}

// NewLDAPDirectory checks cfg; it does not call the directory (see Probe). Its errors name the
// variable, never what a file holds.
func NewLDAPDirectory(cfg LDAPConfig) (*LDAPDirectory, error) {
	u, err := url.Parse(cfg.URL)
	if err != nil || u.Host == "" || u.User != nil || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return nil, errors.New("LDAP_URL must be a URL such as ldaps://dc.example:636, without credentials, DN, query or fragment")
	}
	d := &LDAPDirectory{cfg: cfg, addr: u.Scheme + "://" + u.Host}
	switch u.Scheme {
	case "ldaps":
	case "ldap":
		d.startTLS = true // never a password in clear: ldap:// is upgraded by StartTLS, or refused
	default:
		return nil, errors.New("LDAP_URL: the scheme must be ldaps, or ldap (with StartTLS)")
	}
	sc, ok := schemas[cfg.Schema]
	if !ok {
		return nil, errors.New("LDAP_SCHEMA must be ad or rfc")
	}
	d.schema = sc
	for _, v := range [][2]string{{"LDAP_BIND_DN", cfg.BindDN}, {"LDAP_USER_BASE_DN", cfg.UserBaseDN}, {"LDAP_GROUP_BASE_DN", cfg.GroupBaseDN}} {
		if _, err := NormalizeDN(v[1]); err != nil {
			return nil, fmt.Errorf("%s is not a DN", v[0])
		}
	}
	if _, err := readSecretFile("LDAP_BIND_PASSWORD_FILE", cfg.BindPasswordFile); err != nil {
		return nil, err
	}
	d.tls = &tls.Config{MinVersion: tls.VersionTLS12, ServerName: u.Hostname()}
	if cfg.CAFile != "" {
		pem, err := os.ReadFile(cfg.CAFile)
		if err != nil {
			return nil, fmt.Errorf("LDAP_CA_FILE cannot be read: %v", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, errors.New("LDAP_CA_FILE holds no PEM certificate")
		}
		d.tls.RootCAs = pool
	}
	return d, nil
}

// Where is the directory, as it may be written down.
func (d *LDAPDirectory) Where() string { return d.addr }

// NormalizeDN is the form group DNs are compared in: parsed, then lowercased (distinguishedNameMatch
// is case-insensitive for the attributes directories use in group names).
func NormalizeDN(dn string) (string, error) {
	if strings.TrimSpace(dn) == "" {
		return "", errors.New("an empty DN")
	}
	p, err := ldap.ParseDN(dn)
	if err != nil || len(p.RDNs) == 0 {
		return "", errors.New("not a DN")
	}
	return strings.ToLower(p.String()), nil
}

// NormalizeRoleMap returns roles with its keys as NormalizeDN writes them; a key that is not a DN,
// or two keys for the same group, is refused.
func NormalizeRoleMap(roles application.RoleMap) (application.RoleMap, error) {
	out := application.RoleMap{}
	for group, r := range roles {
		k, err := NormalizeDN(group)
		if err != nil {
			return nil, fmt.Errorf("the role map key %q is not a group DN", group)
		}
		if _, dup := out[k]; dup {
			return nil, fmt.Errorf("the role map names the group %q twice", group)
		}
		out[k] = r
	}
	return out, nil
}

// connect dials the directory, over TLS, with LDAPTimeout; ctx closes it.
func (d *LDAPDirectory) connect(ctx context.Context) (*ldap.Conn, func(), error) {
	dialer := &net.Dialer{Timeout: LDAPTimeout}
	conn, err := ldap.DialURL(d.addr, ldap.DialWithDialer(dialer), ldap.DialWithTLSConfig(d.tls))
	if err != nil {
		return nil, nil, fmt.Errorf("the directory at %s cannot be reached: %v", d.addr, err)
	}
	conn.SetTimeout(LDAPTimeout)
	if d.startTLS {
		if err := conn.StartTLS(d.tls); err != nil {
			conn.Close()
			return nil, nil, fmt.Errorf("the directory at %s does not complete StartTLS: %v", d.addr, err)
		}
	}
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	return conn, func() { stop(); conn.Close() }, nil
}

// serviceBind binds the service account, its password read again (a rotated password is taken).
func (d *LDAPDirectory) serviceBind(conn *ldap.Conn) error {
	pw, err := readSecretFile("LDAP_BIND_PASSWORD_FILE", d.cfg.BindPasswordFile)
	if err != nil {
		return err
	}
	if err := conn.Bind(d.cfg.BindDN, pw); err != nil {
		return fmt.Errorf("the service account cannot bind to %s: %s", d.addr, ldapCause(err))
	}
	return nil
}

// Probe binds the service account: the directory answers, over TLS, and the account is accepted.
func (d *LDAPDirectory) Probe(ctx context.Context) error {
	conn, done, err := d.connect(ctx)
	if err != nil {
		return err
	}
	defer done()
	return d.serviceBind(conn)
}

// Authenticate implements application.Directory.
func (d *LDAPDirectory) Authenticate(ctx context.Context, username, password string) (application.DirectoryIdentity, error) {
	var none application.DirectoryIdentity
	if password == "" { // an anonymous bind (RFC 4513 §5.1.2): never sent
		return none, application.ErrDirectoryRejected
	}
	conn, done, err := d.connect(ctx)
	if err != nil {
		return none, err
	}
	defer done()
	if err := d.serviceBind(conn); err != nil {
		return none, err
	}

	attrs := append([]string{d.schema.idAttribute}, d.schema.nameAttrs...)
	res, err := conn.Search(ldap.NewSearchRequest(d.cfg.UserBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 2, int(LDAPTimeout/time.Second), false,
		fmt.Sprintf(d.schema.userFilter, ldap.EscapeFilter(username)), attrs, nil))
	switch {
	case ldap.IsErrorWithCode(err, ldap.LDAPResultSizeLimitExceeded):
		return none, application.ErrDirectoryRejected // more than one: which would it be?
	case err != nil:
		return none, fmt.Errorf("the user search at %s failed: %s", d.addr, ldapCause(err))
	case len(res.Entries) != 1:
		return none, application.ErrDirectoryRejected
	}
	entry := res.Entries[0]
	id := stableID(d.schema.idAttribute, entry)
	if id == "" {
		return none, fmt.Errorf("the directory at %s gave no %s for the user", d.addr, d.schema.idAttribute)
	}

	// The password goes to the directory on a connection of its own, as the user.
	userConn, userDone, err := d.connect(ctx)
	if err != nil {
		return none, err
	}
	defer userDone()
	if err := userConn.Bind(entry.DN, password); err != nil {
		if ldap.IsErrorWithCode(err, ldap.LDAPResultInvalidCredentials) {
			return none, application.ErrDirectoryRejected
		}
		return none, fmt.Errorf("the directory at %s did not complete the user's bind: %s", d.addr, ldapCause(err))
	}

	groups, err := conn.SearchWithPaging(ldap.NewSearchRequest(d.cfg.GroupBaseDN, ldap.ScopeWholeSubtree, ldap.NeverDerefAliases, 0, int(LDAPTimeout/time.Second), false,
		fmt.Sprintf(d.schema.groupFilter, ldap.EscapeFilter(entry.DN)), []string{"1.1"}, nil), 200)
	if err != nil {
		return none, fmt.Errorf("the group search at %s failed: %s", d.addr, ldapCause(err))
	}
	out := application.DirectoryIdentity{ID: id}
	for _, a := range d.schema.nameAttrs {
		if v := entry.GetAttributeValue(a); v != "" {
			out.Name = v
			break
		}
	}
	for _, g := range groups.Entries {
		if k, err := NormalizeDN(g.DN); err == nil {
			out.Groups = append(out.Groups, k)
		}
	}
	return out, nil
}

// stableID is the user's identifier that does not change with its name: objectGUID in the form AD
// writes it (the first three groups little-endian), or entryUUID.
func stableID(attribute string, e *ldap.Entry) string {
	if attribute != "objectGUID" {
		return strings.ToLower(strings.TrimSpace(e.GetAttributeValue(attribute)))
	}
	b := e.GetRawAttributeValue(attribute)
	if len(b) != 16 {
		return ""
	}
	le := func(p []byte) string {
		r := make([]byte, len(p))
		for i := range p {
			r[i] = p[len(p)-1-i]
		}
		return hex.EncodeToString(r)
	}
	return le(b[0:4]) + "-" + le(b[4:6]) + "-" + le(b[6:8]) + "-" + hex.EncodeToString(b[8:10]) + "-" + hex.EncodeToString(b[10:16])
}

// ldapCause is what a directory error says, bounded; go-ldap's errors carry the result code and the
// server's message, never what was sent.
func ldapCause(err error) string {
	msg := err.Error()
	if len(msg) > 300 {
		msg = msg[:300]
	}
	return msg
}

// readSecretFile reads one value from a file only its owner can read. Its errors name the
// variable, never what the file holds.
func readSecretFile(variable, path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", fmt.Errorf("%s cannot be read: %v", variable, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("%s must be a regular file", variable)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return "", fmt.Errorf("%s is readable by its group or by others (mode %#o): make it 0600 or 0400", variable, info.Mode().Perm())
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s cannot be read: %v", variable, err)
	}
	v := strings.TrimRight(string(b), "\r\n")
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return "", fmt.Errorf("%s must hold one value on one line", variable)
	}
	return v, nil
}

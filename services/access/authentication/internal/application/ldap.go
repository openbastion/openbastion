package application

// Directory login (ADR-0061): the directory checks the password and says which groups the user is
// in; only the role map declared here says what that is worth.

import (
	"context"
	"errors"
	"strings"
	"time"
	"unicode"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// DirectoryIdentity is what the directory says of a user whose password it has accepted.
type DirectoryIdentity struct {
	ID     string   // stable: objectGUID (AD) or entryUUID — never the login name, which may change
	Name   string   // to display
	Groups []string // the DNs of its groups, normalized as the role map's keys are
}

// Directory is the port to one LDAP or Active Directory server.
type Directory interface {
	// Authenticate checks username and password against the directory. ErrDirectoryRejected: no
	// such user, more than one, a wrong password, a disabled account — the caller learns nothing
	// more. Any other error: the directory cannot answer now.
	Authenticate(ctx context.Context, username, password string) (DirectoryIdentity, error)
}

var (
	// ErrDirectoryRejected: the directory does not vouch for this username and password.
	ErrDirectoryRejected = errors.New("the directory refused the login")
	// ErrDirectoryOff: no directory is configured.
	ErrDirectoryOff = errors.New("directory login is not configured")
)

// DirectoryEntry is one directory to turn on (ADR-0076). ID "" is the one of the LDAP_* variables.
// AdoptLegacyAccounts: this directory's accounts are those made before ADR-0076 (provider "").
type DirectoryEntry struct {
	ID, Label           string
	Directory           Directory
	Roles               RoleMap
	AdoptLegacyAccounts bool
}

type directoryEntry struct {
	info      ProviderInfo
	directory Directory
	roles     RoleMap
	accounts  string // the identity_provider of its accounts
}

// source is what a second-factor enrollment code of this directory's accounts is issued for:
// "ldap" for the accounts kept under "", "ldap:<id>" otherwise — alice of one directory is not
// alice of another (ADR-0076).
func (d *directoryEntry) source() string {
	if d.accounts == "" {
		return domain.SourceLDAP
	}
	return domain.SourceLDAP + ":" + d.accounts
}

// MaxDirectoryUsername bounds a login name before it reaches the directory.
const MaxDirectoryUsername = 256

// WithDirectory turns directory login on with one directory, the one of the LDAP_* variables;
// roles' keys are group DNs, normalized as the directory returns them.
func (s *AuthenticationService) WithDirectory(d Directory, roles RoleMap) *AuthenticationService {
	return s.WithDirectories([]DirectoryEntry{{Directory: d, Roles: roles}})
}

// WithDirectories turns directory login on with entries (ADR-0076); cmd/authentication has checked
// them: distinct IDs, at most one that adopts the accounts made before.
func (s *AuthenticationService) WithDirectories(entries []DirectoryEntry) *AuthenticationService {
	s.directories = nil
	for _, e := range entries {
		s.directories = append(s.directories, directoryEntry{info: ProviderInfo{ID: e.ID, Label: e.Label}, directory: e.Directory,
			roles: e.Roles, accounts: accountsKey(e.ID, e.AdoptLegacyAccounts || e.ID == "")})
	}
	return s
}

// DirectoryEnabled says whether directory login is configured.
func (s *AuthenticationService) DirectoryEnabled() bool { return len(s.directories) > 0 }

// Directories is what the login screen may show of the directories, in the declared order.
func (s *AuthenticationService) Directories() []ProviderInfo {
	out := make([]ProviderInfo, 0, len(s.directories))
	for _, d := range s.directories {
		out = append(out, d.info)
	}
	return out
}

// directoryFor is the directory id names; with a single directory, id may be empty. Several and
// none named: ErrProviderRequired — never one after the other, which would send a user's password
// to directories that are not theirs (ADR-0076 §8).
func (s *AuthenticationService) directoryFor(id string) (*directoryEntry, error) {
	if len(s.directories) == 0 {
		return nil, ErrDirectoryOff
	}
	if id == "" && len(s.directories) == 1 {
		return &s.directories[0], nil
	}
	if id == "" {
		return nil, ErrProviderRequired
	}
	for i := range s.directories {
		if s.directories[i].info.ID == id {
			return &s.directories[i], nil
		}
	}
	return nil, ErrUnknownProvider
}

// directoryBySource is the directory whose enrollment codes are issued for source ("ldap" or
// "ldap:<id>"); false if none.
func (s *AuthenticationService) directoryBySource(source string) bool {
	for i := range s.directories {
		if s.directories[i].source() == source {
			return true
		}
	}
	return false
}

// LoginLDAP implements POST /auth/ldap/login (ADR-0061) at the directory named directory
// (ADR-0076; empty with a single one). Which directory is decided before any network: none named
// among several, or an unknown one, is refused and no directory is asked. An empty password is
// refused before the directory is asked: to LDAP, a bind with one is an anonymous bind, which
// succeeds (RFC 4513 §5.1.2). No mapped role: ErrNoRole, and no account is made.
func (s *AuthenticationService) LoginLDAP(ctx context.Context, directory, username, password string) (token string, expiresIn time.Duration, err error) {
	d, err := s.directoryFor(directory)
	if err != nil {
		return "", 0, err
	}
	if !directoryUsername(username) || password == "" {
		s.refused(ctx, username)
		return "", 0, ErrDirectoryRejected
	}
	id, err := d.directory.Authenticate(ctx, username, password)
	if errors.Is(err, ErrDirectoryRejected) {
		s.refused(ctx, username)
	}
	if err != nil {
		return "", 0, err
	}
	if id.ID == "" {
		return "", 0, errors.New("the directory gave no stable identifier for the user")
	}
	roles := d.roles.Roles(id.Groups)
	if len(roles) == 0 {
		return "", 0, ErrNoRole
	}
	display := id.Name
	if display == "" {
		display = username
	}
	u, err := s.externalUser(ctx, domain.SourceLDAP, d.accounts, id.ID, display, roles)
	if err != nil {
		return "", 0, err
	}
	// The enrollment code of a directory account is issued for its login name (ADR-0062 §4), at
	// its directory (ADR-0076).
	return s.tokenOrChallenge(ctx, u, roles, d.source(), strings.ToLower(username))
}

// directoryUsername: 1 to MaxDirectoryUsername characters, none a control character.
func directoryUsername(u string) bool {
	if u == "" || len(u) > MaxDirectoryUsername {
		return false
	}
	for _, c := range u {
		if unicode.IsControl(c) || c == unicode.ReplacementChar {
			return false
		}
	}
	return true
}

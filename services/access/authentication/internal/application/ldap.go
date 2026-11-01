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

// MaxDirectoryUsername bounds a login name before it reaches the directory.
const MaxDirectoryUsername = 256

// WithDirectory turns directory login on; roles' keys are group DNs, normalized as the directory
// returns them.
func (s *AuthenticationService) WithDirectory(d Directory, roles RoleMap) *AuthenticationService {
	s.directory, s.ldapRoleMap = d, roles
	return s
}

// DirectoryEnabled says whether directory login is configured.
func (s *AuthenticationService) DirectoryEnabled() bool { return s.directory != nil }

// LoginLDAP implements POST /auth/ldap/login (ADR-0061). An empty password is refused before the
// directory is asked: to LDAP, a bind with one is an anonymous bind, which succeeds (RFC 4513
// §5.1.2). No mapped role: ErrNoRole, and no account is made.
func (s *AuthenticationService) LoginLDAP(ctx context.Context, username, password string) (token string, expiresIn time.Duration, err error) {
	if s.directory == nil {
		return "", 0, ErrDirectoryOff
	}
	if !directoryUsername(username) || password == "" {
		s.refused(ctx, username)
		return "", 0, ErrDirectoryRejected
	}
	id, err := s.directory.Authenticate(ctx, username, password)
	if errors.Is(err, ErrDirectoryRejected) {
		s.refused(ctx, username)
	}
	if err != nil {
		return "", 0, err
	}
	if id.ID == "" {
		return "", 0, errors.New("the directory gave no stable identifier for the user")
	}
	roles := s.ldapRoleMap.Roles(id.Groups)
	if len(roles) == 0 {
		return "", 0, ErrNoRole
	}
	display := id.Name
	if display == "" {
		display = username
	}
	u, err := s.externalUser(ctx, domain.SourceLDAP, id.ID, display, roles)
	if err != nil {
		return "", 0, err
	}
	// The enrollment code of a directory account is issued for its login name (ADR-0062 §4).
	return s.tokenOrChallenge(ctx, u, roles, domain.SourceLDAP, strings.ToLower(username))
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

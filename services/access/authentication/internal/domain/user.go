// Package domain holds the Authentication Service's entities. See
// docs/architecture/data-architecture.md §3 (users, user_roles).
//
// Simplification documented here rather than hidden: docs/architecture/data-architecture.md models
// user_roles as a separate join table against a standalone roles table.
// This increment folds role *names* directly onto User (a user simply
// has a list of role strings) rather than standing up a full roles CRUD
// surface — Authorization already owns what a role can DO (policies);
// Authentication owns which roles a user HAS. Splitting role assignment
// into its own table/service is a straightforward v0.0.1 refinement that
// doesn't change any caller of this package.
package domain

import (
	"context"
	"errors"
	"time"
)

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string // Argon2id encoded string, never the plaintext; empty for an OIDC or a directory account
	Roles        []string

	// IdentitySource says who vouches for the user (docs/architecture/data-architecture.md): "local" (a password here),
	// "oidc" (a provider, ADR-0035) or "ldap" (a directory, ADR-0061). ExternalSubject is the
	// provider's `sub`, or the directory's stable identifier; empty for a local account.
	// IdentityProvider is which provider or directory vouches for it (ADR-0076): a `sub` is unique
	// at its issuer only. Empty: the one of the OIDC_* or LDAP_* variables, or the entry of the
	// providers file that adopts the accounts made before.
	IdentitySource   string
	IdentityProvider string
	ExternalSubject  string
}

// ErrAttemptNotFound: no login under way has this state — never started, already used, or
// forged.
var ErrAttemptNotFound = errors.New("no such login attempt")

const (
	SourceLocal = "local"
	SourceOIDC  = "oidc"
	SourceLDAP  = "ldap" // a directory (LDAP or Active Directory) checks the password, ADR-0061
)

type UserRepository interface {
	Create(ctx context.Context, u *User) error
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByExternalSubject finds the account that provider of source vouches for as subject
	// (ADR-0035, ADR-0076): the same subject at another provider is another account.
	GetByExternalSubject(ctx context.Context, source, provider, subject string) (*User, error)
	// UpdateIdentity replaces the display name and roles of user id — recomputed at each
	// federated login.
	UpdateIdentity(ctx context.Context, id, displayName string, roles []string) error
}

// LoginAttempt is a federated login under way (ADR-0035): what the callback must match.
type LoginAttempt struct {
	State     string
	Verifier  string // PKCE code verifier
	Nonce     string
	Provider  string // the provider it was started at, the only one its code is exchanged with (ADR-0076)
	ExpiresAt time.Time
}

// LoginAttemptRepository keeps login attempts until their callback, once.
type LoginAttemptRepository interface {
	SaveAttempt(ctx context.Context, a LoginAttempt) error
	// TakeAttempt removes and returns the attempt of state; ErrAttemptNotFound if there is none.
	// Taken once: a second callback with the same state finds nothing.
	TakeAttempt(ctx context.Context, state string) (LoginAttempt, error)
}

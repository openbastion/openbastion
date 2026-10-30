// Package domain holds the Authentication Service's entities. See
// OpenBastion_06_Modele_Donnees.md §3 (users, user_roles).
//
// Simplification documented here rather than hidden: doc 06 models
// user_roles as a separate join table against a standalone roles table.
// This increment folds role *names* directly onto User (a user simply
// has a list of role strings) rather than standing up a full roles CRUD
// surface — Authorization already owns what a role can DO (policies);
// Authentication owns which roles a user HAS. Splitting role assignment
// into its own table/service is a straightforward v1.0 refinement that
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
	PasswordHash string // Argon2id encoded string, never the plaintext; empty for an OIDC account
	Roles        []string

	// IdentitySource says who vouches for the user (doc 06): "local" (a password here) or
	// "oidc" (a provider, ADR-0035). ExternalSubject is the provider's `sub` for an OIDC
	// account, empty for a local one.
	IdentitySource  string
	ExternalSubject string
}

// ErrAttemptNotFound: no login under way has this state — never started, already used, or
// forged.
var ErrAttemptNotFound = errors.New("no such login attempt")

const (
	SourceLocal = "local"
	SourceOIDC  = "oidc"
)

type UserRepository interface {
	Create(ctx context.Context, u *User) error
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)

	// GetByExternalSubject finds the account a provider's subject belongs to (ADR-0035).
	GetByExternalSubject(ctx context.Context, source, subject string) (*User, error)
	// UpdateIdentity replaces the display name and roles of user id — recomputed at each
	// federated login.
	UpdateIdentity(ctx context.Context, id, displayName string, roles []string) error
}

// LoginAttempt is a federated login under way (ADR-0035): what the callback must match.
type LoginAttempt struct {
	State     string
	Verifier  string // PKCE code verifier
	Nonce     string
	ExpiresAt time.Time
}

// LoginAttemptRepository keeps login attempts until their callback, once.
type LoginAttemptRepository interface {
	SaveAttempt(ctx context.Context, a LoginAttempt) error
	// TakeAttempt removes and returns the attempt of state; ErrAttemptNotFound if there is none.
	// Taken once: a second callback with the same state finds nothing.
	TakeAttempt(ctx context.Context, state string) (LoginAttempt, error)
}

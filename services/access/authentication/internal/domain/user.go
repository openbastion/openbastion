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

import "context"

type User struct {
	ID           string
	Username     string
	DisplayName  string
	PasswordHash string // Argon2id encoded string, never the plaintext
	Roles        []string
}

type UserRepository interface {
	Create(ctx context.Context, u *User) error
	GetByUsername(ctx context.Context, username string) (*User, error)
	GetByID(ctx context.Context, id string) (*User, error)
}

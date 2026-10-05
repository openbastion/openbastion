// Package application implements the Authentication Service's use cases.
// See OpenBastion_05_OpenAPI.md §2 (POST /auth/login) and
// OpenBastion_07_Interfaces_Inter_Services.md's RequestContext (§2),
// whose actor_user_id/actor_roles are resolved from VerifyToken.
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type PasswordHasher interface {
	Hash(password string) (string, error)
	Verify(encoded, password string) error
}

// TokenIssuer intentionally exchanges only plain values, not a shared
// struct, so this layer stays independent of how infrastructure encodes
// a token on the wire (see infrastructure.TokenIssuer's doc comment).
type TokenIssuer interface {
	Issue(userID, username string, roles []string, expiresAt time.Time) (token string, err error)
	Verify(token string) (userID, username string, roles []string, expiresAt time.Time, err error)
}

var ErrInvalidCredentials = errors.New("invalid username or password")

type AuthenticationService struct {
	users  domain.UserRepository
	hasher PasswordHasher
	tokens TokenIssuer
	ttl    time.Duration
}

func NewAuthenticationService(users domain.UserRepository, hasher PasswordHasher, tokens TokenIssuer, ttl time.Duration) *AuthenticationService {
	return &AuthenticationService{users: users, hasher: hasher, tokens: tokens, ttl: ttl}
}

// CreateUser onboards a local account. Real deployments delegate identity
// to LDAP/AD/Entra ID/OIDC/SAML or SCIM provisioning (doc 00 §4.7); MVP
// scope is OIDC-or-local (doc 04 §2) — this covers the local half, which
// this sandbox exercises directly since no external OIDC provider is
// reachable here either.
func (s *AuthenticationService) CreateUser(ctx context.Context, username, displayName, password string, roles []string) (*domain.User, error) {
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	u := &domain.User{ID: randomID("user"), Username: username, DisplayName: displayName, PasswordHash: hash, Roles: roles}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Login implements POST /auth/login (doc 05 §2). It returns the same
// ErrInvalidCredentials whether the username doesn't exist or the
// password is wrong — never revealing which, a basic enumeration
// defense.
func (s *AuthenticationService) Login(ctx context.Context, username, password string) (token string, expiresIn time.Duration, err error) {
	u, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		return "", 0, ErrInvalidCredentials
	}
	if err := s.hasher.Verify(u.PasswordHash, password); err != nil {
		return "", 0, ErrInvalidCredentials
	}
	expiresAt := time.Now().UTC().Add(s.ttl)
	token, err = s.tokens.Issue(u.ID, u.Username, u.Roles, expiresAt)
	if err != nil {
		return "", 0, err
	}
	return token, s.ttl, nil
}

// VerifyToken is what the API Gateway calls on every authenticated
// request to resolve the caller's identity — the Gateway trusts only
// this, never anything a client claims about itself in a request body
// (doc 07 §2, RequestContext.actor_user_id/actor_roles).
func (s *AuthenticationService) VerifyToken(ctx context.Context, token string) (userID, username string, roles []string, err error) {
	userID, username, roles, _, err = s.tokens.Verify(token)
	return userID, username, roles, err
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

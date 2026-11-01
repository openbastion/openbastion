// Package application implements the Authentication Service's use cases.
// See docs/api/rest/openapi.yaml (POST /auth/login) and
// docs/api/grpc/README.md's RequestContext (§2),
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

	// Federated login (ADR-0035); nil oidc = off.
	oidc     OIDCProvider
	roleMap  RoleMap
	attempts domain.LoginAttemptRepository
	now      func() time.Time

	// Directory login (ADR-0061); nil directory = off.
	directory   Directory
	ldapRoleMap RoleMap

	// The second factor (ADR-0062); nil mfa = off.
	mfaRoles map[string]bool
	mfa      domain.MFARepository
	sealer   SecretSealer

	// The audit (ADR-0064); nil writes nothing.
	audit    AuditEmitter
	refusals RefusalBudget
}

// WithClock replaces the clock; for tests.
func (s *AuthenticationService) WithClock(now func() time.Time) *AuthenticationService {
	s.now = now
	return s
}

func (s *AuthenticationService) clock() time.Time {
	if s.now != nil {
		return s.now().UTC()
	}
	return time.Now().UTC()
}

func NewAuthenticationService(users domain.UserRepository, hasher PasswordHasher, tokens TokenIssuer, ttl time.Duration) *AuthenticationService {
	return &AuthenticationService{users: users, hasher: hasher, tokens: tokens, ttl: ttl}
}

// CreateUser onboards a local account. Real deployments delegate identity
// to LDAP/AD/Entra ID/OIDC/SAML or SCIM provisioning (docs/architecture/system-overview.md); MVP
// scope is OIDC-or-local (docs/roadmap.md §2) — this covers the local half, which
// this sandbox exercises directly since no external OIDC provider is
// reachable here either.
func (s *AuthenticationService) CreateUser(ctx context.Context, username, displayName, password string, roles []string) (*domain.User, error) {
	hash, err := s.hasher.Hash(password)
	if err != nil {
		return nil, err
	}
	u := &domain.User{ID: randomID("user"), Username: username, DisplayName: displayName, PasswordHash: hash, Roles: roles, IdentitySource: domain.SourceLocal}
	if err := s.users.Create(ctx, u); err != nil {
		return nil, err
	}
	return u, nil
}

// Login implements POST /auth/login (docs/api/rest/openapi.yaml). It returns the same
// ErrInvalidCredentials whether the username doesn't exist or the
// password is wrong — never revealing which, a basic enumeration
// defense.
func (s *AuthenticationService) Login(ctx context.Context, username, password string) (token string, expiresIn time.Duration, err error) {
	u, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		s.refused(ctx, username)
		return "", 0, ErrInvalidCredentials
	}
	// An account a provider or a directory vouches for has no password here (ADR-0035, ADR-0061).
	// An empty source is a local account of before ADR-0035.
	if (u.IdentitySource != "" && u.IdentitySource != domain.SourceLocal) || u.PasswordHash == "" {
		s.refused(ctx, username)
		return "", 0, ErrInvalidCredentials
	}
	if err := s.hasher.Verify(u.PasswordHash, password); err != nil {
		s.refused(ctx, username)
		return "", 0, ErrInvalidCredentials
	}
	// A role that requires the second factor: a challenge, not a token (ADR-0062).
	return s.tokenOrChallenge(ctx, u, u.Roles, domain.SourceLocal, u.Username)
}

// VerifyToken is what the API Gateway calls on every authenticated
// request to resolve the caller's identity — the Gateway trusts only
// this, never anything a client claims about itself in a request body
// (docs/api/grpc/README.md §2, RequestContext.actor_user_id/actor_roles).
func (s *AuthenticationService) VerifyToken(ctx context.Context, token string) (userID, username string, roles []string, err error) {
	userID, username, roles, _, err = s.tokens.Verify(token)
	return userID, username, roles, err
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

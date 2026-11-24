package application

import (
	"context"
	"errors"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// AuthorizationContext is the minimal, current identity state another trusted
// service needs to ask Authorization for a decision. It deliberately excludes
// profile and credential material.
type AuthorizationContext struct {
	UserID string
	Exists bool
	Active bool
	Roles  []string
}

// GetAuthorizationContext returns current roles, never token-cached roles.
// Missing and disabled identities carry no roles; repository failures are not
// converted into an inactive identity because callers must fail closed.
func (s *AuthenticationService) GetAuthorizationContext(ctx context.Context, userID string) (AuthorizationContext, error) {
	u, err := s.users.GetByID(ctx, userID)
	if errors.Is(err, domain.ErrUserNotFound) {
		return AuthorizationContext{UserID: userID, Roles: []string{}}, nil
	}
	if err != nil {
		return AuthorizationContext{}, err
	}
	if u.DisabledAt != nil {
		return AuthorizationContext{UserID: userID, Exists: true, Roles: []string{}}, nil
	}
	return AuthorizationContext{UserID: userID, Exists: true, Active: true, Roles: append([]string{}, u.Roles...)}, nil
}

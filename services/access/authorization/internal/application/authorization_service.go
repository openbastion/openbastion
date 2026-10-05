// Package application implements Authorization.CheckAccess
// (proto/authz/v1/authorization.proto, doc 07 §8) — the single decision
// point every other service defers to (doc 00 §9, Guide Sécurité §5).
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"time"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

type AuthorizationService struct {
	policies domain.PolicyRepository
}

func NewAuthorizationService(policies domain.PolicyRepository) *AuthorizationService {
	return &AuthorizationService{policies: policies}
}

// CreatePolicy mirrors POST /policies (doc 05 §2).
func (s *AuthorizationService) CreatePolicy(ctx context.Context, name, role, resourcePattern string, effect domain.Effect, createdBy string) (*domain.Policy, error) {
	p := &domain.Policy{
		ID: randomID("policy"), Name: name, Role: role,
		ResourcePattern: resourcePattern, Effect: effect, CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.policies.Create(ctx, p); err != nil {
		return nil, err
	}
	return p, nil
}

// Decision mirrors CheckAccessResponse (doc 07 §8).
type Decision struct {
	Allowed          bool
	RequiresApproval bool // always false in MVP — no Workflow Service yet (doc 04 §2)
	Reason           string
}

// CheckAccess evaluates every policy attached to any of the caller's roles
// against resource. The rule, in order:
//
//  1. No matching policy at all -> deny (deny-by-default, Guide Sécurité §5:
//     "un rôle sans politique associée n'ouvre l'accès à rien").
//  2. Any matching policy with Effect == deny -> deny, even if another
//     matching policy allows it. An explicit deny always wins.
//  3. Otherwise, any matching policy with Effect == allow -> allow.
func (s *AuthorizationService) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (Decision, error) {
	policies, err := s.policies.ForRoles(ctx, actorRoles)
	if err != nil {
		return Decision{}, err
	}

	matched := false
	allowed := false
	for _, p := range policies {
		if !p.Matches(resource) {
			continue
		}
		matched = true
		if p.Effect == domain.EffectDeny {
			return Decision{Allowed: false, Reason: "explicit deny policy matched: " + p.Name}, nil
		}
		if p.Effect == domain.EffectAllow {
			allowed = true
		}
	}

	if !matched {
		return Decision{Allowed: false, Reason: "no policy matches this resource for the caller's roles"}, nil
	}
	if !allowed {
		return Decision{Allowed: false, Reason: "matching policies present but none grant allow"}, nil
	}
	return Decision{Allowed: true, Reason: "allow policy matched"}, nil
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

// Package application implements Authorization.CheckAccess
// (proto/authz/v1/authorization.proto, docs/api/grpc/README.md §8) — the single decision
// point every other service defers to (docs/security/security-overview.md, docs/security/authorization-rbac-abac.md).
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

type AuthorizationService struct {
	policies domain.PolicyRepository
}

func NewAuthorizationService(policies domain.PolicyRepository) *AuthorizationService {
	return &AuthorizationService{policies: policies}
}

// PolicyAdminResource gates who may create or modify policies — the
// platform's own root of trust, deliberately distinct from any resource a
// policy itself can grant (an actor with "allow" on "vault:account:*"
// gains nothing here). Unlike vault's "vault:account-admin:<id>" (ADR-0003
// companion, services/vault/password-vault/internal/application), there is
// nothing to parametrize by target: policy creation is a single
// platform-wide capability, not one per resource. See
// BootstrapAdminPolicy for how the very first grant of this resource is
// made, and NOTES_SANDBOX.md for the full rationale.
const PolicyAdminResource = "authz:policy-admin"

// requirePolicyAdmin is CreatePolicy's gate. It calls CheckAccess
// in-process — Authorization is its own authority here, there is no
// network hop and so no "unreachable" failure mode distinct from a
// repository error, which already propagates as an error (fail-closed:
// an error from the policy store is never treated as an allow).
func (s *AuthorizationService) requirePolicyAdmin(ctx context.Context, actorRoles []string) error {
	decision, err := s.CheckAccess(ctx, actorRoles, PolicyAdminResource, "authz:policy:create")
	if err != nil {
		return fmt.Errorf("checking access (fail-closed): %w", err)
	}
	if !decision.Allowed {
		return fmt.Errorf("%w: %s", ErrAccessDenied, decision.Reason)
	}
	return nil
}

// ErrAccessDenied: the caller may not create policies (ADR-0043: its message, the reason, is
// what a client reads; any other error is a failure, never shown).
var ErrAccessDenied = errors.New("access denied")

// CreatePolicy mirrors POST /policies (docs/api/rest/openapi.yaml). Closes the RBAC gap
// this increment addresses: creating a policy — the platform's own
// access-control configuration — now requires the caller to hold
// PolicyAdminResource itself, exactly like any other administrative
// write in the system (docs/security/authorization-rbac-abac.md: "aucun service ne réimplémente
// sa propre logique d'autorisation" — this service is no exception to
// its own rule, even for its own writes).
func (s *AuthorizationService) CreatePolicy(ctx context.Context, actorRoles []string, name, role, resourcePattern string, effect domain.Effect, createdBy string) (*domain.Policy, error) {
	if err := s.requirePolicyAdmin(ctx, actorRoles); err != nil {
		return nil, err
	}
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

// BootstrapAdminPolicy grants role the right to create further policies —
// the one seam where the chicken-and-egg problem CreatePolicy's own RBAC
// gate would otherwise create is deliberately broken: on a brand-new
// deployment, the policy store is empty, so no actor could ever pass
// requirePolicyAdmin, and nobody could ever create the first policy at
// all. This method bypasses that gate, but ONLY when the store currently
// has zero policies of ANY kind — not just zero policies for
// PolicyAdminResource. On every other call it is a deliberate no-op,
// so a later caller (including a compromised one) can never use it to
// mint itself a fresh admin role on a system that has already been
// initialized. It is meant to run exactly once, at first boot
// (cmd/authorization/main.go, BOOTSTRAP_ADMIN_ROLE), the same way a real
// deployment hands its first operator a break-glass credential out of
// band (cf. HashiCorp Vault's root token at init, Keycloak's bootstrap
// admin) — here expressed as a policy because that is this system's own
// native unit of access, not a special-cased credential type.
func (s *AuthorizationService) BootstrapAdminPolicy(ctx context.Context, role, createdBy string) (created bool, err error) {
	count, err := s.policies.Count(ctx)
	if err != nil {
		return false, fmt.Errorf("checking existing policy count (fail-closed): %w", err)
	}
	if count > 0 {
		return false, nil
	}
	p := &domain.Policy{
		ID: randomID("policy"), Name: "bootstrap-admin", Role: role,
		ResourcePattern: PolicyAdminResource, Effect: domain.EffectAllow, CreatedBy: createdBy,
		CreatedAt: time.Now().UTC(),
	}
	if err := s.policies.Create(ctx, p); err != nil {
		return false, err
	}
	return true, nil
}

// Decision mirrors CheckAccessResponse (docs/api/grpc/README.md §8).
type Decision struct {
	Allowed          bool
	RequiresApproval bool // always false in MVP — no Workflow Service yet (docs/roadmap.md §2)
	Reason           string
}

// CheckAccess evaluates every policy attached to any of the caller's roles
// against resource. The rule, in order:
//
//  1. No matching policy at all -> deny (deny-by-default, docs/security/authorization-rbac-abac.md:
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

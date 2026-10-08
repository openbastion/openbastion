package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
)

// testAdminRole is the role newTestService bootstraps — every existing
// test in this file that only cares about CheckAccess behavior creates
// its fixture policies as this role, so none of those tests need to
// reason about the RBAC gate on CreatePolicy itself. Tests that exercise
// that gate directly use newRawTestService instead (unbootstrapped).
const testAdminRole = "test-admin"

func newRawTestService() *application.AuthorizationService {
	return application.NewAuthorizationService(infrastructure.NewInMemoryStore())
}

func newTestService() *application.AuthorizationService {
	svc := newRawTestService()
	if _, err := svc.BootstrapAdminPolicy(context.Background(), testAdminRole, "test-harness"); err != nil {
		panic("test harness: BootstrapAdminPolicy: " + err.Error())
	}
	return svc
}

// erroringPolicyRepository fails every call — used to prove CreatePolicy
// and BootstrapAdminPolicy fail closed when the policy store itself is
// unreachable, rather than silently treating a storage error as "no
// policies yet" or "no policy matched".
type erroringPolicyRepository struct{}

func (erroringPolicyRepository) Create(ctx context.Context, p *domain.Policy) error {
	return errors.New("store unreachable")
}
func (erroringPolicyRepository) ForRoles(ctx context.Context, roles []string) ([]*domain.Policy, error) {
	return nil, errors.New("store unreachable")
}
func (erroringPolicyRepository) Count(ctx context.Context) (int, error) {
	return 0, errors.New("store unreachable")
}

func TestCheckAccess_DeniesByDefaultWithNoPolicy(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	decision, err := svc.CheckAccess(ctx, []string{"dba"}, "vault:account:prod-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny-by-default when no policy exists for the role")
	}
}

func TestCheckAccess_AllowsWhenAnAllowPolicyMatches(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	if _, err := svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1"); err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	decision, err := svc.CheckAccess(ctx, []string{"dba"}, "vault:account:prod-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !decision.Allowed {
		t.Fatalf("expected allow, got deny: %s", decision.Reason)
	}
}

func TestCheckAccess_WildcardDoesNotMatchUnrelatedResource(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

	decision, err := svc.CheckAccess(ctx, []string{"dba"}, "vault:account:staging-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny — the allow policy is scoped to prod-db-*, not staging-db-*")
	}
}

func TestCheckAccess_RoleWithoutMatchingRoleGetsNoAccess(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

	// Caller has a DIFFERENT role than the one the policy is attached to.
	decision, err := svc.CheckAccess(ctx, []string{"network-engineer"}, "vault:account:prod-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected deny — the allow policy belongs to a role the caller does not have")
	}
}

func TestCheckAccess_ExplicitDenyOverridesAllow(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()

	// A broad allow for the role, and a narrower explicit deny that should
	// win even though it's evaluated after the allow in creation order —
	// order of policy creation must not matter (Guide Sécurité §5).
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-all-db", "dba", "vault:account:*", domain.EffectAllow, "admin1")
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-no-payments-db", "dba", "vault:account:payments-db-*", domain.EffectDeny, "admin1")

	decision, err := svc.CheckAccess(ctx, []string{"dba"}, "vault:account:payments-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("expected the explicit deny to override the broader allow")
	}

	// The broader allow should still apply to a resource the deny doesn't cover.
	decision2, err := svc.CheckAccess(ctx, []string{"dba"}, "vault:account:reporting-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if !decision2.Allowed {
		t.Fatalf("expected the broad allow to still apply outside the deny's scope: %s", decision2.Reason)
	}
}

func TestCheckAccess_NewRoleWithNoPoliciesHasZeroAccess(t *testing.T) {
	// Guide Sécurité §5's explicit example: a newly created role must not
	// inherit any implicit access, including from other roles' policies.
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

	decision, err := svc.CheckAccess(ctx, []string{"brand-new-role"}, "vault:account:prod-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a role with zero policies must have zero access")
	}
}

// -- RBAC on CreatePolicy itself, and its bootstrap -------------------------
//
// The gap this increment closes: POST /policies used to accept any
// caller. These tests prove (1) an unbootstrapped store refuses every
// CreatePolicy call, no matter the caller's role; (2) BootstrapAdminPolicy
// is the only way past that, and only on a truly empty store; (3) once
// bootstrapped, the granted role can create further policies and an
// ungranted role still cannot; (4) both paths fail closed, never open,
// when the policy store itself errors.

func TestCreatePolicy_DeniedWithoutPolicyAdminAccess(t *testing.T) {
	svc := newRawTestService()
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, []string{"dba"}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")
	if err == nil {
		t.Fatal("expected CreatePolicy to be denied on an unbootstrapped store, regardless of caller role")
	}
}

func TestCreatePolicy_DeniedForARoleThatOnlyHasUnrelatedAccess(t *testing.T) {
	// Holding "allow" on some other resource must not imply anything about
	// authz:policy-admin — the same non-inference rule as vault's
	// TestOnboardAccount_SessionCreationRightsAloneDoNotGrantAdminAccess.
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

	_, err := svc.CreatePolicy(ctx, []string{"dba"}, "dba-more", "dba", "vault:account:staging-*", domain.EffectAllow, "dba")
	if err == nil {
		t.Fatal("expected CreatePolicy to be denied — the 'dba' role has vault access, not authz:policy-admin")
	}
}

func TestBootstrapAdminPolicy_CreatesFirstPolicyOnEmptyStoreAndGrantsAccess(t *testing.T) {
	svc := newRawTestService()
	ctx := context.Background()

	created, err := svc.BootstrapAdminPolicy(ctx, "platform-admin", "system-bootstrap")
	if err != nil {
		t.Fatalf("BootstrapAdminPolicy: %v", err)
	}
	if !created {
		t.Fatal("expected BootstrapAdminPolicy to create the first policy on an empty store")
	}

	if _, err := svc.CreatePolicy(ctx, []string{"platform-admin"}, "first-real-policy", "dba", "vault:account:*", domain.EffectAllow, "platform-admin"); err != nil {
		t.Fatalf("expected the bootstrapped role to be able to create further policies: %v", err)
	}
}

func TestBootstrapAdminPolicy_NoOpWhenAnyPolicyAlreadyExists(t *testing.T) {
	svc := newTestService() // newTestService already bootstraps testAdminRole
	ctx := context.Background()

	// A second bootstrap attempt, even for a completely different role,
	// must be a no-op — otherwise any later caller could mint itself a
	// fresh admin role on an already-initialized system, defeating the
	// whole point of gating CreatePolicy in the first place.
	created, err := svc.BootstrapAdminPolicy(ctx, "attacker-role", "system-bootstrap")
	if err != nil {
		t.Fatalf("BootstrapAdminPolicy: %v", err)
	}
	if created {
		t.Fatal("expected BootstrapAdminPolicy to be a no-op once any policy already exists")
	}

	decision, err := svc.CheckAccess(ctx, []string{"attacker-role"}, application.PolicyAdminResource, "authz:policy:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("re-running bootstrap on a non-empty store must never grant a new admin role")
	}
}

func TestCreatePolicy_FailsClosedWhenPolicyStoreErrors(t *testing.T) {
	svc := application.NewAuthorizationService(erroringPolicyRepository{})
	ctx := context.Background()

	_, err := svc.CreatePolicy(ctx, []string{"platform-admin"}, "p", "dba", "vault:account:*", domain.EffectAllow, "x")
	if err == nil {
		t.Fatal("expected CreatePolicy to fail closed when the policy store is unreachable")
	}
}

func TestBootstrapAdminPolicy_FailsClosedWhenPolicyStoreErrors(t *testing.T) {
	svc := application.NewAuthorizationService(erroringPolicyRepository{})
	ctx := context.Background()

	if _, err := svc.BootstrapAdminPolicy(ctx, "platform-admin", "system"); err == nil {
		t.Fatal("expected BootstrapAdminPolicy to fail closed when Count itself errors — never assume an empty store on error")
	}
}

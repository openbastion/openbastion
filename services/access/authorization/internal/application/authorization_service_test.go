package application_test

import (
	"context"
	"testing"

	"github.com/openbastion/openbastion/services/access/authorization/internal/application"
	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/internal/infrastructure"
)

func newTestService() *application.AuthorizationService {
	return application.NewAuthorizationService(infrastructure.NewInMemoryStore())
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

	if _, err := svc.CreatePolicy(ctx, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1"); err != nil {
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
	_, _ = svc.CreatePolicy(ctx, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

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
	_, _ = svc.CreatePolicy(ctx, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

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
	_, _ = svc.CreatePolicy(ctx, "dba-all-db", "dba", "vault:account:*", domain.EffectAllow, "admin1")
	_, _ = svc.CreatePolicy(ctx, "dba-no-payments-db", "dba", "vault:account:payments-db-*", domain.EffectDeny, "admin1")

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
	_, _ = svc.CreatePolicy(ctx, "dba-prod-db", "dba", "vault:account:prod-db-*", domain.EffectAllow, "admin1")

	decision, err := svc.CheckAccess(ctx, []string{"brand-new-role"}, "vault:account:prod-db-01", "session:create")
	if err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	if decision.Allowed {
		t.Fatal("a role with zero policies must have zero access")
	}
}

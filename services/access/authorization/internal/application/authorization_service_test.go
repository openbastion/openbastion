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

	if _, err := svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1"); err != nil {
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
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1")

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
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1")

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
	// order of policy creation must not matter (docs/security/authorization-rbac-abac.md).
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-all-db", "dba", "vault:account:*", "*", domain.EffectAllow, "admin1")
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-no-payments-db", "dba", "vault:account:payments-db-*", "*", domain.EffectDeny, "admin1")

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
	// docs/security/authorization-rbac-abac.md's explicit example: a newly created role must not
	// inherit any implicit access, including from other roles' policies.
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1")

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

	_, err := svc.CreatePolicy(ctx, []string{"dba"}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1")
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
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "dba-prod-db", "dba", "vault:account:prod-db-*", "*", domain.EffectAllow, "admin1")

	_, err := svc.CreatePolicy(ctx, []string{"dba"}, "dba-more", "dba", "vault:account:staging-*", "*", domain.EffectAllow, "dba")
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

	if _, err := svc.CreatePolicy(ctx, []string{"platform-admin"}, "first-real-policy", "dba", "vault:account:*", "*", domain.EffectAllow, "platform-admin"); err != nil {
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

	_, err := svc.CreatePolicy(ctx, []string{"platform-admin"}, "p", "dba", "vault:account:*", "*", domain.EffectAllow, "x")
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

func TestCheckAccess_RequiresResourceAndActionToMatch(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	_, err := svc.CreatePolicy(ctx, []string{testAdminRole}, "audit-read", "auditor", "audit:secret-injections:all", "audit:secret-injections:read", domain.EffectAllow, "admin1")
	if err != nil {
		t.Fatalf("CreatePolicy: %v", err)
	}

	cases := []struct {
		name, resource, action string
		allowed                bool
	}{
		{"both dimensions match", "audit:secret-injections:all", "audit:secret-injections:read", true},
		{"resource matches but action does not", "audit:secret-injections:all", "audit:secret-injections:delete", false},
		{"action matches but resource does not", "audit:secret-injections:other", "audit:secret-injections:read", false},
		{"neither dimension matches", "session:all", "session:read", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.CheckAccess(ctx, []string{"auditor"}, tc.resource, tc.action)
			if err != nil {
				t.Fatalf("CheckAccess: %v", err)
			}
			if got.Allowed != tc.allowed {
				t.Fatalf("Allowed=%v, want %v (%s)", got.Allowed, tc.allowed, got.Reason)
			}
		})
	}
}

func TestCheckAccess_ActionDenyOverridesActionAllowOnlyWhenBothMatch(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "audit-all", "auditor", "audit:*", "audit:*", domain.EffectAllow, "admin1")
	_, _ = svc.CreatePolicy(ctx, []string{testAdminRole}, "audit-delete-deny", "auditor", "audit:secret-injections:*", "audit:secret-injections:delete", domain.EffectDeny, "admin1")

	denied, err := svc.CheckAccess(ctx, []string{"auditor"}, "audit:secret-injections:all", "audit:secret-injections:delete")
	if err != nil {
		t.Fatal(err)
	}
	if denied.Allowed {
		t.Fatal("explicit action deny must override broad allow")
	}
	allowed, err := svc.CheckAccess(ctx, []string{"auditor"}, "audit:secret-injections:all", "audit:secret-injections:read")
	if err != nil {
		t.Fatal(err)
	}
	if !allowed.Allowed {
		t.Fatalf("read should remain allowed: %s", allowed.Reason)
	}
}

func TestCheckAccess_EmptyActionOrResourceIsDenied(t *testing.T) {
	svc := newTestService()
	for _, tc := range []struct{ name, resource, action string }{{"empty action", "vault:account:a", ""}, {"empty resource", "", "session:create"}} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := svc.CheckAccess(context.Background(), []string{testAdminRole}, tc.resource, tc.action)
			if err != nil {
				t.Fatal(err)
			}
			if got.Allowed {
				t.Fatal("empty resource/action must fail closed")
			}
		})
	}
}

func TestCreatePolicy_RejectsInvalidActionPattern(t *testing.T) {
	svc := newTestService()
	_, err := svc.CreatePolicy(context.Background(), []string{testAdminRole}, "bad", "auditor", "audit:all", "audit:*:read", domain.EffectAllow, "admin1")
	if !errors.Is(err, domain.ErrInvalidPolicyPattern) {
		t.Fatalf("CreatePolicy error=%v, want invalid pattern", err)
	}
}

// ADR-0131: Capabilities answers exact and prefix questions in order, on one read of the store.
func TestCapabilities_AnswersEachQuestionInOrder(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	for _, p := range []struct {
		name, role, resource, action string
		effect                       domain.Effect
	}{
		{"ops-rotate-one", "ops", "vault:account-admin:acc_1", "vault:account:rotate", domain.EffectAllow},
		{"ops-list", "ops", "vault:account-admin:*", "vault:account:list", domain.EffectAllow},
		{"ops-no-delete", "ops", "vault:account-admin:*", "vault:account:delete", domain.EffectDeny},
	} {
		if _, err := svc.CreatePolicy(ctx, []string{testAdminRole}, p.name, p.role, p.resource, p.action, p.effect, "admin"); err != nil {
			t.Fatalf("CreatePolicy %s: %v", p.name, err)
		}
	}
	got, err := svc.Capabilities(ctx, []string{"ops"}, []application.CapabilityQuery{
		{Resource: "vault:account-admin:", Action: "vault:account:rotate", Prefix: true}, // one account: some
		{Resource: "vault:account-admin:*", Action: "vault:account:list"},                // exact
		{Resource: "vault:account-admin:", Action: "vault:account:delete", Prefix: true}, // denied everywhere
		{Resource: "authz:policy-admin", Action: "authz:policy:create"},                  // nothing
		{Resource: "vault:account-admin:acc_2", Action: "vault:account:rotate"},          // exact: not this one
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []bool{true, true, false, false, false}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("answers %v, want %v", got, want)
		}
	}
}

func TestCapabilities_RefusesAnUnboundedOrEmptyListAndFailsClosed(t *testing.T) {
	svc := newTestService()
	ctx := context.Background()
	if _, err := svc.Capabilities(ctx, []string{"ops"}, nil); !errors.Is(err, application.ErrInvalidCapabilityQuery) {
		t.Fatalf("no query: %v", err)
	}
	many := make([]application.CapabilityQuery, application.MaxCapabilityQueries+1)
	for i := range many {
		many[i] = application.CapabilityQuery{Resource: "r", Action: "a"}
	}
	if _, err := svc.Capabilities(ctx, []string{"ops"}, many); !errors.Is(err, application.ErrInvalidCapabilityQuery) {
		t.Fatalf("%d queries: %v", len(many), err)
	}
	if _, err := svc.Capabilities(ctx, []string{"ops"}, []application.CapabilityQuery{{Resource: "", Action: "a"}}); !errors.Is(err, application.ErrInvalidCapabilityQuery) {
		t.Fatalf("empty resource: %v", err)
	}
	broken := application.NewAuthorizationService(erroringPolicyRepository{})
	if got, err := broken.Capabilities(ctx, []string{"platform-admin"}, []application.CapabilityQuery{{Resource: "r", Action: "a"}}); err == nil || got != nil {
		t.Fatalf("a failing store must answer nothing: %v %v", got, err)
	}
}

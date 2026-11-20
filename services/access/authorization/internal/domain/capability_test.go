package domain_test

import (
	"testing"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

// ADR-0131: "does any resource under this prefix allow this action?" is an upper bound of what
// CheckAccess would allow on some resource of the prefix, used only to shape the Admin UI.
func TestAllowsSomeUnder(t *testing.T) {
	allow := func(resource, action string) *domain.Policy {
		return &domain.Policy{Name: "a " + resource, ResourcePattern: resource, ActionPattern: action, Effect: domain.EffectAllow}
	}
	deny := func(resource, action string) *domain.Policy {
		return &domain.Policy{Name: "d " + resource, ResourcePattern: resource, ActionPattern: action, Effect: domain.EffectDeny}
	}
	const prefix, action = "vault:account-admin:", "vault:account:rotate"
	cases := []struct {
		name     string
		policies []*domain.Policy
		want     bool
	}{
		{"no policy: deny by default", nil, false},
		{"allow on every account", []*domain.Policy{allow("vault:account-admin:*", action)}, true},
		{"allow on one account is some", []*domain.Policy{allow("vault:account-admin:acc_1", action)}, true},
		{"allow on a narrower wildcard", []*domain.Policy{allow("vault:account-admin:prod-*", action)}, true},
		{"allow on a wider wildcard covers the prefix", []*domain.Policy{allow("vault:*", action)}, true},
		{"allow with an action wildcard", []*domain.Policy{allow("vault:account-admin:*", "vault:account:*")}, true},
		{"allow on another action grants nothing", []*domain.Policy{allow("vault:account-admin:*", "vault:account:delete")}, false},
		{"allow on another prefix grants nothing", []*domain.Policy{allow("vault:account:*", action)}, false},
		{"a look-alike prefix is not the prefix", []*domain.Policy{allow("vault:account-admin", action)}, false},
		{"a deny covering the whole prefix wins", []*domain.Policy{allow("vault:account-admin:acc_1", action), deny("vault:account-admin:*", action)}, false},
		{"a wider deny covering the prefix wins", []*domain.Policy{allow("vault:account-admin:*", action), deny("vault:*", "*")}, false},
		{"a deny on one account leaves the others", []*domain.Policy{allow("vault:account-admin:*", action), deny("vault:account-admin:acc_1", action)}, true},
		{"a deny on another action changes nothing", []*domain.Policy{allow("vault:account-admin:*", action), deny("vault:account-admin:*", "vault:account:delete")}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.AllowsSomeUnder(tc.policies, prefix, action); got != tc.want {
				t.Fatalf("AllowsSomeUnder()=%v, want %v", got, tc.want)
			}
		})
	}
	if domain.AllowsSomeUnder([]*domain.Policy{allow("*", "*")}, "", action) {
		t.Fatal("an empty prefix must not be a question")
	}
	if domain.AllowsSomeUnder([]*domain.Policy{allow("*", "*")}, prefix, "") {
		t.Fatal("an empty action must not be a question")
	}
}

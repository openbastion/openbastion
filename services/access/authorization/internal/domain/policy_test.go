package domain_test

import (
	"testing"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
)

func TestPolicyMatchesRequiresBothDimensions(t *testing.T) {
	p := domain.Policy{ResourcePattern: "audit:secret-injections:all", ActionPattern: "audit:secret-injections:read"}
	cases := []struct {
		name, resource, action string
		want                   bool
	}{
		{"exact match", "audit:secret-injections:all", "audit:secret-injections:read", true},
		{"resource only", "audit:secret-injections:all", "audit:secret-injections:delete", false},
		{"action only", "audit:secret-injections:other", "audit:secret-injections:read", false},
		{"empty action", "audit:secret-injections:all", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := p.Matches(tc.resource, tc.action); got != tc.want {
				t.Fatalf("Matches()=%v, want %v", got, tc.want)
			}
		})
	}
}

func TestValidPattern(t *testing.T) {
	for _, pattern := range []string{"*", "vault:account:*", "audit:secret-injections:read", "a-1_b.c"} {
		if !domain.ValidPattern(pattern) {
			t.Errorf("ValidPattern(%q)=false", pattern)
		}
	}
	for _, pattern := range []string{"", "vault:*:prod", "a**", "a*b*"} {
		if domain.ValidPattern(pattern) {
			t.Errorf("ValidPattern(%q)=true", pattern)
		}
	}
}

func TestPolicyMatchesTrailingWildcardsOnBothDimensions(t *testing.T) {
	p := domain.Policy{ResourcePattern: "vault:account:prod-*", ActionPattern: "session:*"}
	if !p.Matches("vault:account:prod-db", "session:create") {
		t.Fatal("expected both trailing wildcards to match")
	}
	if p.Matches("vault:account:staging-db", "session:create") {
		t.Fatal("resource wildcard must remain scoped")
	}
	if p.Matches("vault:account:prod-db", "vault:read") {
		t.Fatal("action wildcard must remain scoped")
	}
}

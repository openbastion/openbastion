// Package domain holds the Authorization Service's entities. See
// docs/architecture/data-architecture.md §3 (policies) and docs/security/authorization-rbac-abac.md
// (deny-by-default, principe du moindre privilège).
package domain

import (
	"strings"
	"time"
)

type Effect string

const (
	EffectAllow Effect = "allow"
	EffectDeny  Effect = "deny"
)

// Policy mirrors the policies table. A policy is scoped to a single role —
// CheckAccess evaluates it against the caller's roles, never against an
// individual user directly (docs/architecture/data-architecture.md §3).
type Policy struct {
	ID              string
	Name            string
	Role            string
	ResourcePattern string
	Effect          Effect
	CreatedBy       string
	CreatedAt       time.Time
}

// Matches reports whether resource satisfies p's ResourcePattern. Patterns
// support a single trailing "*" wildcard (e.g. "vault:account:prod-*"); any
// other pattern is matched exactly. This is deliberately the simplest rule
// that covers docs/architecture/system-overview.md's example patterns — a richer glob/ABAC matcher is a
// v1.0 concern (docs/security/security-overview.md), not an MVP one.
func (p Policy) Matches(resource string) bool {
	if strings.HasSuffix(p.ResourcePattern, "*") {
		prefix := strings.TrimSuffix(p.ResourcePattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	return p.ResourcePattern == resource
}

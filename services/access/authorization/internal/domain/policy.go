// Package domain holds the Authorization Service's entities. See
// OpenBastion_06_Modele_Donnees.md §3 (policies) and Guide Sécurité §5
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
// individual user directly (doc 06 §3).
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
// that covers doc 00's example patterns — a richer glob/ABAC matcher is a
// v1.0 concern (doc 00 §9), not an MVP one.
func (p Policy) Matches(resource string) bool {
	if strings.HasSuffix(p.ResourcePattern, "*") {
		prefix := strings.TrimSuffix(p.ResourcePattern, "*")
		return strings.HasPrefix(resource, prefix)
	}
	return p.ResourcePattern == resource
}

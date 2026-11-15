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
	ActionPattern   string
	Effect          Effect
	CreatedBy       string
	CreatedAt       time.Time
}

// Matches reports whether both resource and action satisfy the policy patterns.
// Patterns support a single trailing "*" wildcard; any other pattern is exact.
// A policy is applicable only when BOTH dimensions match (ADR-0114).
func (p Policy) Matches(resource, action string) bool {
	return matchesPattern(p.ResourcePattern, resource) && matchesPattern(p.ActionPattern, action)
}

// ValidPattern accepts a non-empty exact value or a value with one trailing wildcard.
func ValidPattern(pattern string) bool {
	if pattern == "" {
		return false
	}
	index := strings.IndexByte(pattern, '*')
	return index == -1 || (index == len(pattern)-1 && strings.LastIndexByte(pattern, '*') == index)
}

func matchesPattern(pattern, value string) bool {
	if pattern == "" || value == "" {
		return false
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(value, prefix)
	}
	return pattern == value
}

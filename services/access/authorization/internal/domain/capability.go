package domain

import "strings"

// AllowsSomeUnder answers ADR-0131's question for the Admin UI: may the policies' roles take
// action on at least one resource whose name starts with prefix?
//
// It is an upper bound of CheckAccess on the resources of the prefix, never a grant: every
// action is still decided by CheckAccess on its own resource. The rule follows CheckAccess:
//
//   - nothing matches: false (deny by default);
//   - a deny policy for the action whose resource pattern covers the whole prefix (a trailing
//     wildcard that the prefix starts with): false, whatever allows;
//   - otherwise true when an allow policy for the action can match some resource of the prefix.
//
// A deny on part of the prefix does not make it false: the rest may still be allowed. So the
// answer may say "some" where every allowed resource is also denied one by one; the UI then shows
// an action the server refuses, which is what it did before this decision.
func AllowsSomeUnder(policies []*Policy, prefix, action string) bool {
	if prefix == "" || action == "" {
		return false
	}
	allowed := false
	for _, p := range policies {
		if p == nil || !matchesPattern(p.ActionPattern, action) {
			continue
		}
		switch p.Effect {
		case EffectDeny:
			if coversPrefix(p.ResourcePattern, prefix) {
				return false
			}
		case EffectAllow:
			if overlapsPrefix(p.ResourcePattern, prefix) {
				allowed = true
			}
		}
	}
	return allowed
}

// coversPrefix: every resource under prefix matches pattern.
func coversPrefix(pattern, prefix string) bool {
	if !strings.HasSuffix(pattern, "*") {
		return false
	}
	return strings.HasPrefix(prefix, strings.TrimSuffix(pattern, "*"))
}

// overlapsPrefix: at least one resource under prefix matches pattern.
func overlapsPrefix(pattern, prefix string) bool {
	if pattern == "" {
		return false
	}
	if !strings.HasSuffix(pattern, "*") {
		return strings.HasPrefix(pattern, prefix) && len(pattern) > len(prefix)
	}
	stem := strings.TrimSuffix(pattern, "*")
	return strings.HasPrefix(stem, prefix) || strings.HasPrefix(prefix, stem)
}

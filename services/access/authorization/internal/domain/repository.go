package domain

import "context"

type PolicyRepository interface {
	Create(ctx context.Context, p *Policy) error
	// ForRoles returns every policy whose Role is in roles — CheckAccess
	// evaluates only these, never the full policy set (deny-by-default:
	// a role with zero matching policies gets zero access, doc 06 §3).
	ForRoles(ctx context.Context, roles []string) ([]*Policy, error)
}

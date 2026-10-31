package domain

import (
	"context"
	"errors"
)

// ErrAlreadyExists: a policy for this role, resource pattern and effect exists already
// (ADR-0043); the database's own message, which names its constraint, never reaches a client.
var ErrAlreadyExists = errors.New("a policy for this role, resource pattern and effect already exists")

type PolicyRepository interface {
	Create(ctx context.Context, p *Policy) error
	// ForRoles returns every policy whose Role is in roles — CheckAccess
	// evaluates only these, never the full policy set (deny-by-default:
	// a role with zero matching policies gets zero access, docs/architecture/data-architecture.md §3).
	ForRoles(ctx context.Context, roles []string) ([]*Policy, error)
	// Count reports how many policies exist in total. Its only consumer
	// is AuthorizationService.BootstrapAdminPolicy, which must act only
	// on a truly empty store — see that method's doc comment.
	Count(ctx context.Context) (int, error)
}

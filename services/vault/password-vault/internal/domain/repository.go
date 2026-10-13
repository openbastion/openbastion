package domain

import (
	"context"
	"errors"
)

// ErrNotFound is returned by any repository when the requested entity does
// not exist. Concrete infrastructure implementations map their own
// not-found conditions onto this sentinel so application/ never depends
// on a specific storage engine's error type.
var ErrNotFound = errors.New("not found")

type AccountRepository interface {
	Get(ctx context.Context, id string) (*PrivilegedAccount, error)
	Create(ctx context.Context, a *PrivilegedAccount) error

	// List returns accounts ordered deterministically by id, one page at
	// a time (page is 1-based; pageSize is validated/capped by the
	// caller — application.VaultService.ListAccounts), plus the total
	// count across all pages. Mirrors GET /vault/accounts (doc 05 §2).
	// Excludes disabled accounts — see Disable's doc comment for why
	// that symmetry matters.
	List(ctx context.Context, page, pageSize int) (accounts []*PrivilegedAccount, totalItems int, err error)

	// Disable soft-deletes an account by setting DisabledAt rather than
	// removing the row — mirrors DELETE /vault/accounts/{id} (doc 05
	// §2). A hard delete would cascade (vault_secrets references
	// privileged_accounts ON DELETE CASCADE, migrations/001_init.sql),
	// destroying the exact secret-version history a PAM system exists
	// to preserve for audit. DisabledAt already existed on
	// PrivilegedAccount and in the DDL before this method did —
	// populated by nothing until now; see NOTES_SANDBOX.md. Disabling
	// an already-disabled (or unknown) account's existence is checked
	// by the caller, not here; Disable itself is idempotent.
	Disable(ctx context.Context, id string) error
}

type SecretRepository interface {
	CurrentVersion(ctx context.Context, accountID string) (*SecretVersion, error)
	AddVersion(ctx context.Context, s *SecretVersion) error
	SupersedeCurrent(ctx context.Context, accountID string) error
}

type ScopeRepository interface {
	Save(ctx context.Context, g *ScopeGrant) error
	// ConsumeIfValid atomically checks and marks a scope token consumed —
	// it must reject an unknown, expired, already-consumed, or wrong-proxy
	// token in a single operation, so there is no window for a race
	// between "check" and "consume" (ADR-0003).
	ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*ScopeGrant, error)
}

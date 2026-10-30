package domain

import (
	"context"
	"errors"
	"time"
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

	// MarkRotated sets LastRotatedAt to now — the same
	// previously-unpopulated-field shape as Disable/DisabledAt above,
	// found while wiring lastRotatedAt into the HTTP response
	// (interfaces/http.go's accountResponse): the column has existed in
	// the DDL since migrations/001_init.sql and PostgresStore.Get has
	// always scanned it, but nothing ever wrote to it — Rotate
	// (application.VaultService) created new secret versions without
	// ever touching the account row itself. Called by Rotate only after
	// the new version has been stored successfully, so a failed
	// rotation never falsely claims to have rotated. Idempotent, like
	// Disable; existence is checked by the caller.
	MarkRotated(ctx context.Context, id string) error

	// SetReconciliation names the reconciliation account of id (ADR-0037).
	SetReconciliation(ctx context.Context, id, reconciliationID string) error

	// SetHostKey pins the host key of id's target (ADR-0039).
	SetHostKey(ctx context.Context, id, hostKey string) error

	// ListDueForRotation is at most limit scheduled, enabled accounts due at now (ADR-0040)
	// and not taken since now-retryAfter, the longest overdue first.
	ListDueForRotation(ctx context.Context, now time.Time, retryAfter time.Duration, limit int) ([]*PrivilegedAccount, error)
	// ClaimRotation takes id for a scheduled rotation at now — compare-and-swap: false when it
	// is no longer due, or another taker had it since now-retryAfter.
	ClaimRotation(ctx context.Context, id string, now time.Time, retryAfter time.Duration) (bool, error)
}

// ErrRotationInProgress: the account already has a pending rotation (ADR-0037).
var ErrRotationInProgress = errors.New("a rotation of this account is already in progress")

type SecretRepository interface {
	// CurrentVersion is the secret injected: never a pending one.
	CurrentVersion(ctx context.Context, accountID string) (*SecretVersion, error)
	AddVersion(ctx context.Context, s *SecretVersion) error
	SupersedeCurrent(ctx context.Context, accountID string) error

	// AddPending writes a rotation's new secret beside the current one (ADR-0037); a second
	// pending version for the same account is ErrRotationInProgress.
	AddPending(ctx context.Context, s *SecretVersion) error
	// PendingVersion is the account's pending version, or nil.
	PendingVersion(ctx context.Context, accountID string) (*SecretVersion, error)
	// PromotePending makes the pending version current and supersedes the old one, in ONE
	// step: there is no moment without a current secret.
	PromotePending(ctx context.Context, accountID string, version int) error
	// DiscardPending forgets a pending version the target never took.
	DiscardPending(ctx context.Context, accountID string, version int) error
}

type ScopeRepository interface {
	Save(ctx context.Context, g *ScopeGrant) error
	// ConsumeIfValid atomically checks and marks a scope token consumed —
	// it must reject an unknown, expired, already-consumed, or wrong-proxy
	// token in a single operation, so there is no window for a race
	// between "check" and "consume" (ADR-0003).
	ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*ScopeGrant, error)
}

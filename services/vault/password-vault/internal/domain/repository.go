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

// ErrKeysUnavailable: the keys that seal the secrets cannot be reached (Transit, ADR-0049) — a
// failure of a dependency, never a refusal: nothing was sealed nor opened, and the same call may
// succeed once they are back.
var ErrKeysUnavailable = errors.New("the keys that seal the secrets are unavailable")

// ErrAlreadyExists: an account with this id — or this name on this target — exists already
// (ADR-0043). Both stores return it; the database's own message never reaches a client.
var ErrAlreadyExists = errors.New("an account with this id, or with this name on this target, already exists")

type AccountRepository interface {
	Get(ctx context.Context, id string) (*PrivilegedAccount, error)
	Create(ctx context.Context, a *PrivilegedAccount) error

	// List returns accounts ordered deterministically by id, one page at
	// a time (page is 1-based; pageSize is validated/capped by the
	// caller — application.VaultService.ListAccounts), plus the total
	// count across all pages. Mirrors GET /vault/accounts (docs/api/rest/openapi.yaml).
	// Excludes disabled accounts — see Disable's doc comment for why
	// that symmetry matters.
	List(ctx context.Context, page, pageSize int) (accounts []*PrivilegedAccount, totalItems int, err error)

	// Disable soft-deletes an account by setting DisabledAt rather than
	// removing the row — mirrors DELETE /vault/accounts/{id} (docs/api/rest/openapi.yaml
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
	// Disable; existence is checked by the caller. It also sets the
	// count of failed scheduled rotations back to 0 (ADR-0041), and
	// clears a rotation owed (ADR-0044).
	MarkRotated(ctx context.Context, id string) error

	// SetReconciliation names the reconciliation account of id (ADR-0037).
	SetReconciliation(ctx context.Context, id, reconciliationID string) error

	// SetHostKey pins the host key of id's target (ADR-0039).
	SetHostKey(ctx context.Context, id, hostKey string) error

	// ListDueForRotation is at most limit enabled accounts to be rotated at now and not taken
	// since now-retryAfter, the longest waiting first: those that owe a rotation (ADR-0044) and,
	// when scheduled is true, those whose schedule is due (ADR-0040).
	ListDueForRotation(ctx context.Context, now time.Time, retryAfter time.Duration, limit int, scheduled bool) ([]*PrivilegedAccount, error)
	// MarkRotationOwed records that id owes a rotation since at (ADR-0044); an earlier date
	// already recorded is kept. A NEW debt lifts the delay after an attempt (that delay is for
	// failures); a debt already owed keeps it. MarkRotated clears it.
	MarkRotationOwed(ctx context.Context, id string, at time.Time) error
	// ClaimRotation takes id for a scheduled rotation at now — compare-and-swap: false when it
	// is no longer due, or another taker had it since now-retryAfter.
	ClaimRotation(ctx context.Context, id string, now time.Time, retryAfter time.Duration) (bool, error)
	// RecordRotationFailure counts one more scheduled rotation of id that failed, and returns
	// how many have failed in a row (ADR-0041). MarkRotated sets the count back to 0.
	RecordRotationFailure(ctx context.Context, id string) (int, error)
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

	// SealedUnder lists, by id, up to limit versions — current, pending or superseded — whose id
	// comes after afterID and that are sealed under one of keyIDs (ADR-0055): what an earlier key
	// still protects, a page at a time.
	SealedUnder(ctx context.Context, keyIDs []string, afterID string, limit int) ([]*SecretVersion, error)
	// ResealIf replaces a version's material and key, only if it is still sealed under oldKeyID:
	// a compare-and-swap, so that nothing written meanwhile is overwritten. It says whether it did.
	ResealIf(ctx context.Context, versionID, oldKeyID string, material []byte, newKeyID string) (bool, error)
}

type ScopeRepository interface {
	Save(ctx context.Context, g *ScopeGrant) error
	// ConsumeIfValid atomically checks and marks a scope token consumed —
	// it must reject an unknown, expired, already-consumed, or wrong-proxy
	// token in a single operation, so there is no window for a race
	// between "check" and "consume" (ADR-0003).
	ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*ScopeGrant, error)
}

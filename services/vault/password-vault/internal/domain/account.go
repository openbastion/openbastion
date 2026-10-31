// Package domain holds the Password Vault's entities and repository ports.
// It has no dependency on transport, storage engine, or crypto library —
// those live in infrastructure/. See docs/development/repository-structure.md §3.
package domain

import "time"

type RotationPolicy string

const (
	RotationManual    RotationPolicy = "manual"
	RotationPostUse   RotationPolicy = "post_use"
	RotationScheduled RotationPolicy = "scheduled"
)

// PrivilegedAccount mirrors the privileged_accounts table
// (docs/architecture/data-architecture.md §3). Username was not part of the
// original table — a gap discovered while wiring the Session Broker to a
// real SSH proxy (an SSH connection needs a username, docs/architecture/data-architecture.md had no field
// for it) and added here directly rather than worked around again. docs/architecture/data-architecture.md
// and proto/proxy/v1/proxy_control.proto's EstablishSessionRequest have
// since been updated to formally carry it too — see NOTES_SANDBOX.md for
// the full history.
type PrivilegedAccount struct {
	ID             string
	Name           string
	Username       string
	TargetHost     string
	Protocol       string
	RotationPolicy RotationPolicy
	LastRotatedAt  *time.Time
	CreatedAt      time.Time
	DisabledAt     *time.Time

	// ReconciliationAccountID names the account of the same target that can change this
	// one's password (ADR-0037): root, or an account allowed to `sudo chpasswd`. Empty: the
	// account cannot be rotated.
	ReconciliationAccountID string

	// HostKey is the target's SSH host key, pinned (ADR-0039): one normalized
	// authorized_keys line. Empty for an account onboarded before pinning — no session nor
	// rotation reaches its target until one is set.
	HostKey string

	// RotationIntervalDays is how often a scheduled account rotates (ADR-0040): 1 to 365 for
	// RotationScheduled, 0 for any other policy.
	RotationIntervalDays int
	// RotationAttemptedAt is when the Vault last took this account for a scheduled rotation,
	// whatever came of it: an account is not tried again before RotationRetryAfter.
	RotationAttemptedAt *time.Time
	// RotationFailures counts the scheduled rotations that failed in a row (ADR-0041); any
	// rotation that succeeds sets it back to 0.
	RotationFailures int
	// RotationOwedSince is when a session on this account ended and left a rotation owed
	// (ADR-0044); nil: nothing is owed. Any rotation that succeeds clears it.
	RotationOwedSince *time.Time
}

// RotationDue says whether the account is to be rotated at now (ADR-0040, ADR-0044): it owes a
// rotation, or — when scheduled is true — its schedule is due. Never for a disabled account.
// The second value orders the accounts that are: the longest waiting first.
func (a *PrivilegedAccount) RotationDue(now time.Time, scheduled bool) (bool, time.Time) {
	if a.DisabledAt != nil {
		return false, time.Time{}
	}
	if a.RotationOwedSince != nil {
		return true, *a.RotationOwedSince
	}
	if due := a.RotationDueAt(); scheduled && due != nil && !due.After(now) {
		return true, *due
	}
	return false, time.Time{}
}

// RotationDueAt is when a scheduled account is next due: its last rotation, or its creation
// if it never rotated, plus its interval. Nil for an account that is not scheduled.
func (a *PrivilegedAccount) RotationDueAt() *time.Time {
	if a.RotationPolicy != RotationScheduled || a.RotationIntervalDays <= 0 {
		return nil
	}
	from := a.CreatedAt
	if a.LastRotatedAt != nil {
		from = *a.LastRotatedAt
	}
	due := from.Add(time.Duration(a.RotationIntervalDays) * 24 * time.Hour)
	return &due
}

// SecretVersion mirrors the vault_secrets table. EncryptedMaterial is an
// AES-256-GCM envelope; the plaintext exists only transiently, inside
// application's Rotate/FetchCredential use cases (docs/architecture/data-architecture.md §3, Guide
// Sécurité §6).
type SecretVersion struct {
	ID                  string
	PrivilegedAccountID string
	EncryptedMaterial   []byte
	EncryptionKeyID     string
	Version             int
	CreatedAt           time.Time
	SupersededAt        *time.Time

	// Pending is a new secret written beside the current one during a rotation, not yet
	// set and verified on the target (ADR-0037): never injected until it becomes current.
	Pending bool
}

// ScopeGrant mirrors the authorization issued by AuthorizeScope
// (proto/vault/v1/vault.proto) — single-use, tied to one proxy identity.
type ScopeGrant struct {
	Token               string
	SessionID           string
	PrivilegedAccountID string
	ProxyServiceID      string
	ExpiresAt           time.Time
	Consumed            bool
}

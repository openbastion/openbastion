// Package domain holds the Password Vault's entities and repository ports.
// It has no dependency on transport, storage engine, or crypto library —
// those live in infrastructure/. See OpenBastion_02_Arborescence_Depot.md §3.
package domain

import "time"

type RotationPolicy string

const (
	RotationManual    RotationPolicy = "manual"
	RotationPostUse   RotationPolicy = "post_use"
	RotationScheduled RotationPolicy = "scheduled"
)

// PrivilegedAccount mirrors the privileged_accounts table
// (OpenBastion_06_Modele_Donnees.md §3). Username was not part of the
// original table — a gap discovered while wiring the Session Broker to a
// real SSH proxy (an SSH connection needs a username, doc 06 had no field
// for it) and added here directly rather than worked around again. Doc 06
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
}

// SecretVersion mirrors the vault_secrets table. EncryptedMaterial is an
// AES-256-GCM envelope; the plaintext exists only transiently, inside
// application's Rotate/FetchCredential use cases (doc 06 §3, Guide
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

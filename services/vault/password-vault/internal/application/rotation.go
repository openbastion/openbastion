package application

// Rotation reaches the target (ADR-0037): through the account's reconciliation account, as a
// pending version first, made current only once set and verified on the target.

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// TargetChanger is the port to the targets themselves.
type TargetChanger interface {
	// SetPassword logs in to host as admin with adminSecret and sets user's password to
	// newSecret.
	// The target must present hostKey (ADR-0039).
	SetPassword(ctx context.Context, host, hostKey, admin string, adminSecret []byte, user string, newSecret []byte) error
	// Verify logs in to host as user with secret, and says whether the target took it.
	Verify(ctx context.Context, host, hostKey, user string, secret []byte) error
}

// AuditEmitter writes to the audit trail.
type AuditEmitter interface {
	EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error
}

var (
	// ErrNoReconciliation: the account names no usable reconciliation account — it cannot be
	// rotated (a rotation that changes the Vault only is not a rotation).
	ErrNoReconciliation = errors.New("the account has no usable reconciliation account: it cannot be rotated")
	// ErrRotationRefused: the target did not take the new secret; nothing changed.
	ErrRotationRefused = errors.New("the target refused the new secret: nothing changed")
	// ErrRotationUnverified: the new secret was set and could not be verified, or neither
	// secret opens the target any more; it is kept pending for a human or the next rotation.
	ErrRotationUnverified = errors.New("the rotation could not be verified on the target")
	// ErrRotationOff: no way to reach the targets is configured.
	ErrRotationOff = errors.New("rotation is not configured (no way to reach the targets)")
)

// WithRotation lets the Vault reach the targets and write its rotations to the audit trail.
func (s *VaultService) WithRotation(targets TargetChanger, audit AuditEmitter) *VaultService {
	s.targets, s.audit = targets, audit
	return s
}

// OnboardAccountWithReconciliation onboards an account that names its reconciliation account.
func (s *VaultService) OnboardAccountWithReconciliation(ctx context.Context, actorRoles []string, id, name, username, targetHost, protocol string, policy domain.RotationPolicy, initialSecret []byte, reconciliationID string) error {
	if reconciliationID != "" {
		if err := s.checkReconciliation(ctx, id, targetHost, reconciliationID); err != nil {
			return err
		}
	}
	if err := s.OnboardAccount(ctx, actorRoles, id, name, username, targetHost, protocol, policy, initialSecret); err != nil {
		return err
	}
	if reconciliationID == "" {
		return nil
	}
	return s.accounts.SetReconciliation(ctx, id, reconciliationID)
}

// SetReconciliationAccount names (or changes) the reconciliation account of accountID.
func (s *VaultService) SetReconciliationAccount(ctx context.Context, actorRoles []string, accountID, reconciliationID string) error {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:onboard"); err != nil {
		return err
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if err := s.checkReconciliation(ctx, accountID, a.TargetHost, reconciliationID); err != nil {
		return err
	}
	return s.accounts.SetReconciliation(ctx, accountID, reconciliationID)
}

// checkReconciliation: another account, enabled, of the same target.
func (s *VaultService) checkReconciliation(ctx context.Context, accountID, targetHost, reconciliationID string) error {
	if reconciliationID == accountID {
		return fmt.Errorf("%w: an account cannot be its own reconciliation account", ErrNoReconciliation)
	}
	r, err := s.accounts.Get(ctx, reconciliationID)
	if err != nil || r.DisabledAt != nil {
		return fmt.Errorf("%w: %s is not an account of the Vault", ErrNoReconciliation, reconciliationID)
	}
	if r.TargetHost != targetHost {
		return fmt.Errorf("%w: %s is an account of another target", ErrNoReconciliation, reconciliationID)
	}
	return nil
}

// Rotate rotates accountID for whoever holds actorRoles (ADR-0037); see RotateAs.
func (s *VaultService) Rotate(ctx context.Context, actorRoles []string, accountID string, newSecret []byte) error {
	return s.RotateAs(ctx, "", actorRoles, accountID, newSecret)
}

// RotateAs rotates accountID on its target, for actorID holding actorRoles. newSecret is
// generated when empty.
func (s *VaultService) RotateAs(ctx context.Context, actorID string, actorRoles []string, accountID string, newSecret []byte) error {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:rotate"); err != nil {
		return err
	}
	return s.rotate(ctx, actorID, accountID, newSecret)
}

// RotateAfterUse rotates accountID because a session on it ended — only if its policy is
// post_use; any other account is left alone. A system action: no actor.
func (s *VaultService) RotateAfterUse(ctx context.Context, accountID string) (rotated bool, err error) {
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return false, err
	}
	if a.DisabledAt != nil || a.RotationPolicy != domain.RotationPostUse {
		return false, nil
	}
	return true, s.rotate(ctx, "", accountID, nil)
}

func (s *VaultService) rotate(ctx context.Context, actorID, accountID string, newSecret []byte) error {
	if s.targets == nil || s.audit == nil {
		return ErrRotationOff
	}
	account, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if account.DisabledAt != nil {
		return domain.ErrNotFound
	}
	if account.ReconciliationAccountID == "" {
		return ErrNoReconciliation
	}
	if account.HostKey == "" {
		return ErrNoHostKey
	}
	if err := s.checkReconciliation(ctx, accountID, account.TargetHost, account.ReconciliationAccountID); err != nil {
		return err
	}
	if len(newSecret) == 0 {
		if newSecret, err = generateRandomSecret(32); err != nil {
			return err
		}
	}
	if strings.ContainsAny(string(newSecret), ":\r\n") || strings.ContainsAny(account.Username, ":\r\n") {
		return fmt.Errorf("a secret or a user name for a target may not hold ':' or a line break")
	}

	// A pending version left by an earlier rotation is settled first, by the target itself.
	if err := s.settlePending(ctx, actorID, account); err != nil {
		return err
	}
	current, err := s.secrets.CurrentVersion(ctx, accountID)
	if err != nil {
		return err
	}
	admin, err := s.accounts.Get(ctx, account.ReconciliationAccountID)
	if err != nil {
		return err
	}
	adminSecret, err := s.currentSecret(ctx, admin.ID)
	if err != nil {
		return err
	}

	// Fail-closed: nothing touches the target unless the trail says it was asked.
	if err := s.audit.EmitEvent(ctx, actorID, "vault.rotate_requested", "account", accountID, true); err != nil {
		return fmt.Errorf("the audit is unavailable, nothing was rotated: %w", err)
	}
	sealed, err := s.kms.Seal(newSecret)
	if err != nil {
		return err
	}
	pending := &domain.SecretVersion{ID: randomID("secret"), PrivilegedAccountID: accountID, EncryptedMaterial: sealed,
		EncryptionKeyID: s.kms.KeyID(), Version: current.Version + 1}
	if err := s.secrets.AddPending(ctx, pending); err != nil {
		return err
	}
	if err := s.targets.SetPassword(ctx, account.TargetHost, account.HostKey, admin.Username, adminSecret, account.Username, newSecret); err != nil {
		_ = s.secrets.DiscardPending(ctx, accountID, pending.Version)
		s.auditOutcome(ctx, actorID, accountID, false)
		return fmt.Errorf("%w: %v", ErrRotationRefused, err)
	}
	if err := s.targets.Verify(ctx, account.TargetHost, account.HostKey, account.Username, newSecret); err != nil {
		// Set, maybe; not verified: kept pending, settled by the next rotation.
		s.auditOutcome(ctx, actorID, accountID, false)
		return fmt.Errorf("%w: %v", ErrRotationUnverified, err)
	}
	if err := s.secrets.PromotePending(ctx, accountID, pending.Version); err != nil {
		return err
	}
	_ = s.accounts.MarkRotated(ctx, accountID)
	s.auditOutcome(ctx, actorID, accountID, true)
	return nil
}

// settlePending decides a pending version by asking the target: the new secret opens it — it
// becomes current; the old one still does — the pending one is forgotten; neither — nobody
// decides for a human.
func (s *VaultService) settlePending(ctx context.Context, actorID string, account *domain.PrivilegedAccount) error {
	pending, err := s.secrets.PendingVersion(ctx, account.ID)
	if err != nil || pending == nil {
		return err
	}
	newSecret, err := s.kms.Open(pending.EncryptedMaterial)
	if err != nil {
		return err
	}
	if s.targets.Verify(ctx, account.TargetHost, account.HostKey, account.Username, newSecret) == nil {
		if err := s.secrets.PromotePending(ctx, account.ID, pending.Version); err != nil {
			return err
		}
		_ = s.accounts.MarkRotated(ctx, account.ID)
		s.auditOutcome(ctx, actorID, account.ID, true)
		return nil
	}
	old, err := s.currentSecret(ctx, account.ID)
	if err != nil {
		return err
	}
	if s.targets.Verify(ctx, account.TargetHost, account.HostKey, account.Username, old) == nil {
		return s.secrets.DiscardPending(ctx, account.ID, pending.Version)
	}
	return fmt.Errorf("%w: neither the current nor the pending secret opens the target — a human must look", ErrRotationUnverified)
}

func (s *VaultService) currentSecret(ctx context.Context, accountID string) ([]byte, error) {
	v, err := s.secrets.CurrentVersion(ctx, accountID)
	if err != nil {
		return nil, err
	}
	return s.kms.Open(v.EncryptedMaterial)
}

// auditOutcome writes how a rotation ended. Best effort: the outcome has happened on the
// target whatever the trail answers now; the request before it was fail-closed.
func (s *VaultService) auditOutcome(ctx context.Context, actorID, accountID string, success bool) {
	_ = s.audit.EmitEvent(ctx, actorID, "vault.rotate", "account", accountID, success)
}

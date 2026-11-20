package application

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

// ErrNotRDP: a screen profile on an account that is not RDP (ADR-0132).
var ErrNotRDP = errors.New("a screen profile is for RDP accounts only")

// SetScreenProfile sets what a session on an RDP account may use for its screen (ADR-0132): the
// channels and colour depths allowed, and their defaults; nil removes the profile (everything
// allowed). For an administrator of the account (vault:account:screen-profile on
// vault:account-admin:<id>), the change written to the audit before it is made — without the
// audit, nothing changes; a refusal is written too, at best, as for the approval (ADR-0067).
func (s *VaultService) SetScreenProfile(ctx context.Context, actorID string, actorRoles []string, accountID string, profile *domain.ScreenProfile) error {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:screen-profile"); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			if s.audit == nil {
				return fmt.Errorf("%w: cannot audit the refused screen-profile change", ErrAuditUnavailable)
			}
			if auditErr := s.audit.EmitEvent(ctx, actorID, "vault.screen_profile_set", "account", accountID, false); auditErr != nil {
				return fmt.Errorf("%w: cannot audit the refused screen-profile change: %w", ErrAuditUnavailable, auditErr)
			}
		}
		return err
	}
	if profile != nil {
		if err := profile.Validate(); err != nil {
			return err
		}
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if a.DisabledAt != nil {
		return domain.ErrNotFound
	}
	if a.Protocol != "rdp" {
		return ErrNotRDP
	}
	if s.audit == nil {
		return ErrRotationOff
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.screen_profile_set", "account", accountID, true); err != nil {
		return fmt.Errorf("%w (the screen profile was not changed): %w", ErrAuditUnavailable, err)
	}
	if err := s.accounts.SetScreenProfile(ctx, accountID, profile); err != nil {
		return err
	}
	log.Printf("password-vault: account %s screen profile set by %s", accountID, actorID)
	return nil
}

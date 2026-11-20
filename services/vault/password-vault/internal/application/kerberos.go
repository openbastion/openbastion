package application

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

var (
	// ErrKerberosNotRDP: Kerberos settings on an account that is not RDP (ADR-0100).
	ErrKerberosNotRDP = errors.New("Kerberos settings are for RDP accounts only")
	// ErrKerberosNeedsName: the account's pinned target name is an IP address, and a Kerberos
	// service ticket names a host (TERMSRV/<host>).
	ErrKerberosNeedsName = errors.New("Kerberos needs the account's pinned target name to be a DNS name, not an IP address")
)

// SetKerberos sets the realm and KDCs of an RDP account (ADR-0100): its sessions then authenticate
// with Kerberos alone, never NTLM; nil removes them (NTLMv2, as before). For an administrator of
// the account (vault:account:kerberos on vault:account-admin:<id>), the change written to the audit
// before it is made — without the audit, nothing changes; a refusal is written too, at best, as
// for the screen profile (ADR-0132). It returns the settings as stored.
func (s *VaultService) SetKerberos(ctx context.Context, actorID string, actorRoles []string, accountID string, settings *domain.KerberosSettings) (*domain.KerberosSettings, error) {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:kerberos"); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			if s.audit == nil {
				return nil, fmt.Errorf("%w: cannot audit the refused Kerberos change", ErrAuditUnavailable)
			}
			if auditErr := s.audit.EmitEvent(ctx, actorID, "vault.kerberos_set", "account", accountID, false); auditErr != nil {
				return nil, fmt.Errorf("%w: cannot audit the refused Kerberos change: %w", ErrAuditUnavailable, auditErr)
			}
		}
		return nil, err
	}
	var stored *domain.KerberosSettings
	if settings != nil {
		normalized, err := settings.Normalized()
		if err != nil {
			return nil, err
		}
		stored = &normalized
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return nil, err
	}
	if a.DisabledAt != nil {
		return nil, domain.ErrNotFound
	}
	if a.Protocol != "rdp" {
		return nil, ErrKerberosNotRDP
	}
	if stored != nil && net.ParseIP(a.TargetDomain) != nil {
		return nil, ErrKerberosNeedsName
	}
	if s.audit == nil {
		return nil, ErrAuditUnavailable
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.kerberos_set", "account", accountID, true); err != nil {
		return nil, fmt.Errorf("%w (the Kerberos settings were not changed): %w", ErrAuditUnavailable, err)
	}
	if err := s.accounts.SetKerberos(ctx, accountID, stored); err != nil {
		return nil, err
	}
	if stored != nil {
		log.Printf("password-vault: account %s set to Kerberos (realm %s, %d KDC) by %s", accountID, stored.Realm, len(stored.KDCs), actorID)
	} else {
		log.Printf("password-vault: account %s set back to NTLM by %s", accountID, actorID)
	}
	return stored, nil
}

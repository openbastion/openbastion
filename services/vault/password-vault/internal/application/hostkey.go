package application

// Pinning SSH host keys and graphical-target TLS identities (ADR-0039, ADR-0071).

import (
	"context"
	"errors"
	"fmt"
	"log"

	"github.com/openbastion/openbastion/pkg/hostkey"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

var (
	// ErrNoHostKey: an SSH account has no pinned host key; no session nor rotation reaches its
	// target until one is set (ADR-0039).
	ErrNoHostKey = errors.New("the account has no pinned host key: pin one before any session or rotation")
	// ErrBadHostKey: what was given is not an SSH public key.
	ErrBadHostKey = errors.New("not an SSH public key (expected a line such as \"ssh-ed25519 AAAA…\") nor an authority line (\"@cert-authority host.example ssh-ed25519 AAAA…\")")
)

// NormalizeHostKey reads what an administrator pins (pkg/hostkey): one public key ("type base64
// [comment]", as in a .pub file, or a known_hosts line whose host names are dropped), or one
// authority line, "@cert-authority <host name> <key>" (ADR-0048). It returns the line to store
// and the fingerprint to show — the authority's for an authority line. A @revoked line, two
// lines, a pattern or a list for the name, or a key that does not read is ErrBadHostKey.
func NormalizeHostKey(s string) (key, fingerprint string, err error) {
	line, fp, err := hostkey.Normalize(s)
	if err != nil {
		return "", "", ErrBadHostKey
	}
	return line, fp, nil
}

// HostKeyFingerprint is the SHA256 fingerprint of a stored key, or "" for none.
func HostKeyFingerprint(key string) string {
	if key == "" {
		return ""
	}
	_, fp, err := NormalizeHostKey(key)
	if err != nil {
		return ""
	}
	return fp
}

// OnboardInput is an account to onboard. SSH requires HostKey; VNC/RDP use a later audited TLS pin (ADR-0071).
type OnboardInput struct {
	ID, Name, Username, TargetHost, Protocol string
	Policy                                   domain.RotationPolicy
	InitialSecret                            []byte
	ReconciliationAccountID                  string
	HostKey                                  string
	// RotationIntervalDays: required for a scheduled account, refused for any other (ADR-0040).
	RotationIntervalDays int
	// ApprovalRequired: a session on the account waits for another person's approval (ADR-0067).
	ApprovalRequired bool
}

// OnboardPinned validates the protocol-specific onboarding identity. SSH requires a valid host key;
// VNC/RDP are created without a pin and cannot receive a scope until SetTLSPin succeeds.
func (s *VaultService) OnboardPinned(ctx context.Context, actorRoles []string, in OnboardInput) error {
	var key string
	switch in.Protocol {
	case "ssh":
		var err error
		key, _, err = NormalizeHostKey(in.HostKey)
		if err != nil {
			return err
		}
	case "vnc", "rdp":
		if in.HostKey != "" {
			return ErrBadHostKey
		}
		if in.Policy != domain.RotationManual || in.ReconciliationAccountID != "" || in.RotationIntervalDays != 0 {
			return ErrUnsupportedProtocol
		}
	default:
		return ErrUnsupportedProtocol
	}
	if err := checkSchedule(in.Policy, in.RotationIntervalDays); err != nil {
		return err
	}
	if in.Policy == domain.RotationScheduled && in.ReconciliationAccountID == "" {
		return fmt.Errorf("%w: a scheduled account needs one, or it would never rotate", ErrNoReconciliation)
	}
	if in.ReconciliationAccountID != "" {
		if err := s.checkReconciliation(ctx, in.ID, in.TargetHost, in.ReconciliationAccountID); err != nil {
			return err
		}
	}
	return s.onboard(ctx, actorRoles, &domain.PrivilegedAccount{
		ID: in.ID, Name: in.Name, Username: in.Username, TargetHost: in.TargetHost, Protocol: in.Protocol, RotationPolicy: in.Policy,
		ReconciliationAccountID: in.ReconciliationAccountID, HostKey: key, RotationIntervalDays: in.RotationIntervalDays,
		ApprovalRequired: in.ApprovalRequired,
	}, in.InitialSecret)
}

// SetHostKey pins (or re-pins) the host key of accountID's target, for an administrator of the
// account, audited: whoever changes a pin decides which server receives the secret.
func (s *VaultService) SetHostKey(ctx context.Context, actorID string, actorRoles []string, accountID, hostKey string) (fingerprint string, err error) {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:pin"); err != nil {
		return "", err
	}
	key, fp, err := NormalizeHostKey(hostKey)
	if err != nil {
		return "", err
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return "", err
	}
	if a.DisabledAt != nil {
		return "", domain.ErrNotFound
	}
	if a.Protocol != "ssh" {
		return "", ErrUnsupportedProtocol
	}
	if s.audit == nil {
		return "", ErrRotationOff
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.host_key_set", "account", accountID, true); err != nil {
		return "", fmt.Errorf("%w (the host key was not changed): %w", ErrAuditUnavailable, err)
	}
	was := HostKeyFingerprint(a.HostKey) // read before the change: a store may hand out its own record
	if err := s.accounts.SetHostKey(ctx, accountID, key); err != nil {
		return "", err
	}
	log.Printf("password-vault: host key of account %s pinned by %s: %s (was %q)", accountID, actorID, fp, was)
	return fp, nil
}

// Delivered is what the Vault hands a protocol proxy for one session: secret plus target identity.
// SSH uses HostKey; VNC/RDP use TargetUser, TLSCertificateSHA256 and TargetDomain (ADR-0071).
type Delivered struct {
	Type                 string
	Material             []byte
	TargetHost           string
	HostKey              string
	TargetUser           string
	TLSCertificateSHA256 string
	TargetDomain         string
}

// SetApprovalRequired says whether a session on accountID waits for another person's approval,
// with a ticket (ADR-0067) — for an administrator of the account, the change written to the audit
// before it is made (without the audit, nothing changes); a refusal is written too, at best.
func (s *VaultService) SetApprovalRequired(ctx context.Context, actorID string, actorRoles []string, accountID string, required bool) error {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:approval"); err != nil {
		if errors.Is(err, ErrAccessDenied) {
			if s.audit == nil {
				return fmt.Errorf("%w: cannot audit the refused approval-setting change", ErrAuditUnavailable)
			}
			if auditErr := s.audit.EmitEvent(ctx, actorID, "vault.approval_set", "account", accountID, false); auditErr != nil {
				return fmt.Errorf("%w: cannot audit the refused approval-setting change: %w", ErrAuditUnavailable, auditErr)
			}
		}
		return err
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return err
	}
	if a.DisabledAt != nil {
		return domain.ErrNotFound
	}
	if s.audit == nil {
		return ErrRotationOff
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.approval_set", "account", accountID, true); err != nil {
		return fmt.Errorf("%w (the approval setting was not changed): %w", ErrAuditUnavailable, err)
	}
	if err := s.accounts.SetApprovalRequired(ctx, accountID, required); err != nil {
		return err
	}
	log.Printf("password-vault: account %s now %s an approval for its sessions (set by %s)", accountID, map[bool]string{true: "requires", false: "does not require"}[required], actorID)
	return nil
}

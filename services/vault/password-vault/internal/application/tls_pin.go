package application

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"

	"github.com/openbastion/openbastion/pkg/tlspin"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

var (
	ErrNoTLSPin              = errors.New("the account has no pinned TLS certificate and target domain")
	ErrBadTLSPin             = errors.New("invalid TLS certificate SHA-256 fingerprint")
	ErrBadTargetDomain       = errors.New("invalid TLS target domain")
	ErrUnsupportedProtocol   = errors.New("unsupported target protocol for this Vault operation")
	ErrProxyProtocolMismatch = errors.New("proxy identity does not match the account protocol")
)

// NormalizeTLSPin validates a SHA-256 leaf-certificate fingerprint and a DNS/IP
// target name. It returns lowercase hexadecimal and a canonical target name.
func NormalizeTLSPin(fingerprint, targetDomain string) (string, string, error) {
	_, err := tlspin.ParseFingerprint(strings.TrimSpace(fingerprint))
	if err != nil {
		return "", "", ErrBadTLSPin
	}
	canonicalPin := strings.ToLower(strings.TrimSpace(fingerprint))
	domain, err := NormalizeTargetDomain(targetDomain)
	if err != nil {
		return "", "", err
	}
	return canonicalPin, domain, nil
}

// NormalizeTargetDomain accepts an IP literal or an ASCII DNS name, never a URL,
// port, wildcard or empty name. The stored value is what TLS ServerName verifies.
func NormalizeTargetDomain(value string) (string, error) {
	name := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if name == "" || len(name) > 253 || strings.ContainsAny(name, "*/\\ \t\r\n:") {
		if ip := net.ParseIP(name); ip == nil {
			return "", ErrBadTargetDomain
		}
	}
	if ip := net.ParseIP(name); ip != nil {
		return ip.String(), nil
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", ErrBadTargetDomain
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' {
				return "", ErrBadTargetDomain
			}
		}
	}
	return name, nil
}

// SetTLSPin pins or re-pins a VNC/RDP target's certificate leaf and expected name.
// Authorization and the successful audit event precede the database change.
func (s *VaultService) SetTLSPin(ctx context.Context, actorID string, actorRoles []string, accountID, fingerprint, targetDomain string) (string, string, error) {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:pin"); err != nil {
		return "", "", err
	}
	pin, name, err := NormalizeTLSPin(fingerprint, targetDomain)
	if err != nil {
		return "", "", err
	}
	a, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return "", "", err
	}
	if a.DisabledAt != nil {
		return "", "", domain.ErrNotFound
	}
	if a.Protocol != "vnc" && a.Protocol != "rdp" {
		return "", "", ErrUnsupportedProtocol
	}
	if s.audit == nil {
		return "", "", ErrAuditUnavailable
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.tls_pin_set", "account", accountID, true); err != nil {
		return "", "", fmt.Errorf("%w (the TLS pin was not changed): %w", ErrAuditUnavailable, err)
	}
	if err := s.accounts.SetTLSPin(ctx, accountID, pin, name); err != nil {
		return "", "", err
	}
	log.Printf("password-vault: TLS leaf of account %s pinned by %s for %s: %s", accountID, actorID, name, pin)
	return pin, name, nil
}

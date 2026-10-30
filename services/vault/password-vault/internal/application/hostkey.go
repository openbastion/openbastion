package application

// Pinning the target's host key (ADR-0039).

import (
	"context"
	"errors"
	"fmt"
	"log"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

var (
	// ErrNoHostKey: the account has no pinned host key — no session nor rotation reaches its
	// target until one is set (ADR-0039).
	ErrNoHostKey = errors.New("the account has no pinned host key: pin one before any session or rotation")
	// ErrBadHostKey: what was given is not an SSH public key.
	ErrBadHostKey = errors.New("not an SSH public key (expected a line such as \"ssh-ed25519 AAAA…\")")
)

// NormalizeHostKey reads one public key ("type base64 [comment]", as in a .pub file, or a
// known_hosts line: the host names before the key are read as authorized_keys options and
// dropped) and returns it as "type base64" with its SHA256 fingerprint. A known_hosts marker
// (@revoked, @cert-authority) is refused: neither line is the key of one host.
func NormalizeHostKey(s string) (key, fingerprint string, err error) {
	line := strings.TrimSpace(s)
	if line == "" || strings.ContainsAny(line, "\r\n") || strings.HasPrefix(line, "@") {
		return "", "", ErrBadHostKey
	}
	pub, _, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
	if err != nil {
		return "", "", ErrBadHostKey
	}
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(pub))), ssh.FingerprintSHA256(pub), nil
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

// OnboardInput is an account to onboard, its target's host key pinned (ADR-0039).
type OnboardInput struct {
	ID, Name, Username, TargetHost, Protocol string
	Policy                                   domain.RotationPolicy
	InitialSecret                            []byte
	ReconciliationAccountID                  string
	HostKey                                  string
}

// OnboardPinned onboards an account whose target's host key is given: required.
func (s *VaultService) OnboardPinned(ctx context.Context, actorRoles []string, in OnboardInput) error {
	key, _, err := NormalizeHostKey(in.HostKey)
	if err != nil {
		return err
	}
	if err := s.OnboardAccountWithReconciliation(ctx, actorRoles, in.ID, in.Name, in.Username, in.TargetHost, in.Protocol,
		in.Policy, in.InitialSecret, in.ReconciliationAccountID); err != nil {
		return err
	}
	return s.accounts.SetHostKey(ctx, in.ID, key)
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
	if s.audit == nil {
		return "", ErrRotationOff
	}
	if err := s.audit.EmitEvent(ctx, actorID, "vault.host_key_set", "account", accountID, true); err != nil {
		return "", fmt.Errorf("the audit is unavailable, the host key was not changed: %w", err)
	}
	was := HostKeyFingerprint(a.HostKey) // read before the change: a store may hand out its own record
	if err := s.accounts.SetHostKey(ctx, accountID, key); err != nil {
		return "", err
	}
	log.Printf("password-vault: host key of account %s pinned by %s: %s (was %q)", accountID, actorID, fp, was)
	return fp, nil
}

// Delivered is what the Vault hands the proxy for one session: the secret, and the target it
// is for — its address and pinned host key (ADR-0039).
type Delivered struct {
	Type       string
	Material   []byte
	TargetHost string
	HostKey    string
}

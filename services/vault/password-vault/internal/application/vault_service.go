// Package application implements the Password Vault's use cases against
// the domain ports. It knows nothing about HTTP/gRPC (see interfaces/) or
// about a specific storage/crypto engine (see infrastructure/).
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
)

type Encryptor interface {
	KeyID() string
	Seal(plaintext []byte) ([]byte, error)
	Open(ciphertext []byte) ([]byte, error)
}

// AuthorizationClient is the port to Authorization.CheckAccess. Write
// operations on privileged accounts — onboarding and rotation — are
// gated on it: this project deliberately does not rely on the Gateway
// alone to keep unauthorized callers out (NOTES_SANDBOX.md). Fail-closed:
// if Authorization cannot be reached, the write is refused.
type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (allowed bool, reason string, err error)
}

type VaultService struct {
	accounts domain.AccountRepository
	secrets  domain.SecretRepository
	scopes   domain.ScopeRepository
	kms      Encryptor
	authz    AuthorizationClient
}

func NewVaultService(accounts domain.AccountRepository, secrets domain.SecretRepository, scopes domain.ScopeRepository, kms Encryptor, authz AuthorizationClient) *VaultService {
	return &VaultService{accounts: accounts, secrets: secrets, scopes: scopes, kms: kms, authz: authz}
}

// adminResource is deliberately distinct from "vault:account:<id>" (what
// session creation checks) — a role needs an explicit policy on
// "vault:account-admin:*" to onboard or rotate accounts.
func adminResource(accountID string) string {
	return "vault:account-admin:" + accountID
}

func (s *VaultService) requireAdminAccess(ctx context.Context, actorRoles []string, accountID, action string) error {
	allowed, reason, err := s.authz.CheckAccess(ctx, actorRoles, adminResource(accountID), action)
	if err != nil {
		return fmt.Errorf("checking access (fail-closed): %w", err)
	}
	if !allowed {
		return fmt.Errorf("access denied: %s", reason)
	}
	return nil
}

func (s *VaultService) OnboardAccount(ctx context.Context, actorRoles []string, id, name, username, targetHost, protocol string, policy domain.RotationPolicy, initialSecret []byte) error {
	if err := s.requireAdminAccess(ctx, actorRoles, id, "vault:account:onboard"); err != nil {
		return err
	}
	account := &domain.PrivilegedAccount{
		ID: id, Name: name, Username: username, TargetHost: targetHost, Protocol: protocol, RotationPolicy: policy,
	}
	if err := s.accounts.Create(ctx, account); err != nil {
		return err
	}
	return s.storeNewVersion(ctx, id, initialSecret)
}

func (s *VaultService) GetAccount(ctx context.Context, id string) (*domain.PrivilegedAccount, error) {
	return s.accounts.Get(ctx, id)
}

func (s *VaultService) Rotate(ctx context.Context, actorRoles []string, accountID string, newSecret []byte) error {
	if err := s.requireAdminAccess(ctx, actorRoles, accountID, "vault:account:rotate"); err != nil {
		return err
	}
	if _, err := s.accounts.Get(ctx, accountID); err != nil {
		return err
	}
	if len(newSecret) == 0 {
		generated, err := generateRandomSecret(32)
		if err != nil {
			return err
		}
		newSecret = generated
	}
	if err := s.secrets.SupersedeCurrent(ctx, accountID); err != nil {
		return err
	}
	return s.storeNewVersion(ctx, accountID, newSecret)
}

func (s *VaultService) storeNewVersion(ctx context.Context, accountID string, secret []byte) error {
	sealed, err := s.kms.Seal(secret)
	if err != nil {
		return err
	}
	version := 1
	if current, err := s.secrets.CurrentVersion(ctx, accountID); err == nil && current != nil {
		version = current.Version + 1
	}
	return s.secrets.AddVersion(ctx, &domain.SecretVersion{
		ID: randomID("secret"), PrivilegedAccountID: accountID,
		EncryptedMaterial: sealed, EncryptionKeyID: s.kms.KeyID(), Version: version,
	})
}

func (s *VaultService) AuthorizeScope(ctx context.Context, sessionID, accountID, proxyServiceID string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	if _, err := s.accounts.Get(ctx, accountID); err != nil {
		return "", time.Time{}, err
	}
	token = randomID("scope")
	expiresAt = time.Now().UTC().Add(ttl)
	grant := &domain.ScopeGrant{Token: token, SessionID: sessionID, PrivilegedAccountID: accountID, ProxyServiceID: proxyServiceID, ExpiresAt: expiresAt}
	if err := s.scopes.Save(ctx, grant); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *VaultService) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (credType string, material []byte, err error) {
	grant, err := s.scopes.ConsumeIfValid(ctx, scopeToken, callingProxyID)
	if err != nil {
		return "", nil, err
	}
	version, err := s.secrets.CurrentVersion(ctx, grant.PrivilegedAccountID)
	if err != nil {
		return "", nil, err
	}
	plaintext, err := s.kms.Open(version.EncryptedMaterial)
	if err != nil {
		return "", nil, err
	}
	return "password", plaintext, nil
}

func randomID(prefix string) string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return prefix + "_" + hex.EncodeToString(b)
}

func generateRandomSecret(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return []byte(hex.EncodeToString(b)), nil
}

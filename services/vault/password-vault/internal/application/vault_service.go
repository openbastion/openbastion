// Package application implements the Password Vault's use cases against
// the domain ports. It knows nothing about HTTP/gRPC (see interfaces/) or
// about a specific storage/crypto engine (see infrastructure/).
package application

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
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
// ErrAccessDenied: Authorization refused the administrative write (ADR-0043: its message, the
// refusal's reason, is what a client reads). ErrAuditUnavailable: a write that must be on the
// record first was not made, the audit being unreachable.
var (
	ErrAccessDenied     = errors.New("access denied")
	ErrAuditUnavailable = errors.New("the audit is unavailable: nothing was changed")
)

type AuthorizationClient interface {
	CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (allowed bool, reason string, err error)
}

type VaultService struct {
	// now is the clock of the scheduled rotations (ADR-0040); time.Now unless a test sets it.
	now func() time.Time

	accounts domain.AccountRepository
	secrets  domain.SecretRepository
	scopes   domain.ScopeRepository
	kms      Encryptor
	authz    AuthorizationClient

	// targets and audit make rotation reach the target (ADR-0037); nil: no rotation.
	targets TargetChanger
	audit   AuditEmitter

	// window and alertAfter shape the scheduled rotations (ADR-0041); zero values: any time,
	// an alert every DefaultRotationAlertAfter failures.
	window     RotationWindow
	alertAfter int
}

func NewVaultService(accounts domain.AccountRepository, secrets domain.SecretRepository, scopes domain.ScopeRepository, kms Encryptor, authz AuthorizationClient) *VaultService {
	return &VaultService{now: time.Now, accounts: accounts, secrets: secrets, scopes: scopes, kms: kms, authz: authz}
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
		return fmt.Errorf("checking access (fail-closed): %w", err) // a dependency: never shown to a client
	}
	if !allowed {
		return fmt.Errorf("%w: %s", ErrAccessDenied, reason)
	}
	return nil
}

func (s *VaultService) OnboardAccount(ctx context.Context, actorRoles []string, id, name, username, targetHost, protocol string, policy domain.RotationPolicy, initialSecret []byte) error {
	return s.onboard(ctx, actorRoles, &domain.PrivilegedAccount{
		ID: id, Name: name, Username: username, TargetHost: targetHost, Protocol: protocol, RotationPolicy: policy,
	}, initialSecret)
}

// onboard writes the account — every field of it in one write — then its first secret.
func (s *VaultService) onboard(ctx context.Context, actorRoles []string, account *domain.PrivilegedAccount, initialSecret []byte) error {
	id := account.ID
	if err := s.requireAdminAccess(ctx, actorRoles, id, "vault:account:onboard"); err != nil {
		return err
	}
	if err := s.accounts.Create(ctx, account); err != nil {
		return err
	}
	// A freshly created account has no prior secret version by
	// construction — version 1, always, no lookup needed (unlike Rotate
	// below, which must compute this before it changes the very state
	// the lookup would otherwise see).
	return s.storeVersion(ctx, id, initialSecret, 1)
}

// GetAccount returns domain.ErrNotFound for a disabled account exactly as
// it would for an unknown one — a disabled account no longer exists from
// any caller's point of view, admin UI and Session Broker's account
// lookup (AccountLookupHTTPClient.GetAccount, same endpoint) alike. This
// is what makes DisableAccount actually block new session creation
// without touching Session Broker's own code: AuthorizeScope below
// performs the identical check as defense in depth, since it must not
// depend on this method's behavior to stay correct.
func (s *VaultService) GetAccount(ctx context.Context, id string) (*domain.PrivilegedAccount, error) {
	account, err := s.accounts.Get(ctx, id)
	if err != nil {
		return nil, err
	}
	if account.DisabledAt != nil {
		return nil, domain.ErrNotFound
	}
	return account, nil
}

// minPage, minPageSize, maxPageSize, and defaultPageSize mirror doc 05
// §2's Page/PageSize parameter definitions (page: min 1, default 1;
// pageSize: min 1, max 100, default 20) — enforced here, not at the HTTP
// layer, so every caller of ListAccounts (today: password-vault's own
// HTTP handler) gets the same clamping regardless of what it received.
const (
	minPage         = 1
	minPageSize     = 1
	maxPageSize     = 100
	defaultPageSize = 20
)

// ListAccounts requires the same "vault:account-admin:*" access as
// onboarding/rotation (resource "*" — a list is not scoped to one
// account) — unlike GetAccount, which has never been RBAC-gated (an
// existing, unexamined gap this increment does not expand: see
// NOTES_SANDBOX.md). Disabled accounts are excluded by
// domain.AccountRepository.List itself, not filtered here.
func (s *VaultService) ListAccounts(ctx context.Context, actorRoles []string, page, pageSize int) (accounts []*domain.PrivilegedAccount, totalItems int, err error) {
	if err := s.requireAdminAccess(ctx, actorRoles, "*", "vault:account:list"); err != nil {
		return nil, 0, err
	}
	page, pageSize = ClampPage(page, pageSize)
	return s.accounts.List(ctx, page, pageSize)
}

// ClampPage is the pagination rule ListAccounts applies (page < 1 → 1;
// pageSize < 1 → the default 20; pageSize > 100 → 100, doc 05's bounds). It
// is exported so the HTTP layer can report the page and page size actually
// SERVED rather than the ones the caller asked for — without it the list
// response said "page 0, pageSize 0" for a request that sent neither.
func ClampPage(page, pageSize int) (int, int) {
	if page < minPage {
		page = minPage
	}
	if pageSize < minPageSize {
		pageSize = defaultPageSize
	}
	if pageSize > maxPageSize {
		pageSize = maxPageSize
	}
	return page, pageSize
}

// DisableAccount soft-deletes via domain.AccountRepository.Disable — see
// its doc comment for why not a hard delete. Returns domain.ErrNotFound
// if the account is unknown or already disabled, matching Rotate's
// existing not-found semantics (checked via Get, which itself now
// excludes disabled accounts — see GetAccount above).
func (s *VaultService) DisableAccount(ctx context.Context, actorRoles []string, id string) error {
	if err := s.requireAdminAccess(ctx, actorRoles, id, "vault:account:delete"); err != nil {
		return err
	}
	if _, err := s.GetAccount(ctx, id); err != nil {
		return err
	}
	return s.accounts.Disable(ctx, id)
}

func (s *VaultService) storeVersion(ctx context.Context, accountID string, secret []byte, version int) error {
	sealed, err := s.kms.Seal(secret)
	if err != nil {
		return err
	}
	return s.secrets.AddVersion(ctx, &domain.SecretVersion{
		ID: randomID("secret"), PrivilegedAccountID: accountID,
		EncryptedMaterial: sealed, EncryptionKeyID: s.kms.KeyID(), Version: version,
	})
}

func (s *VaultService) AuthorizeScope(ctx context.Context, sessionID, accountID, proxyServiceID string, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	// Checks DisabledAt itself (rather than calling GetAccount) so this
	// stays correct even if GetAccount's own disabled-check were ever
	// changed or removed — a disabled account must never be able to
	// issue a usable credential scope, independent of the account-detail
	// read path.
	account, err := s.accounts.Get(ctx, accountID)
	if err != nil {
		return "", time.Time{}, err
	}
	if account.DisabledAt != nil {
		return "", time.Time{}, domain.ErrNotFound
	}
	// A session that could never be given its secret is not authorized at all (ADR-0039).
	if account.HostKey == "" {
		return "", time.Time{}, ErrNoHostKey
	}
	token = randomID("scope")
	expiresAt = time.Now().UTC().Add(ttl)
	grant := &domain.ScopeGrant{Token: token, SessionID: sessionID, PrivilegedAccountID: accountID, ProxyServiceID: proxyServiceID, ExpiresAt: expiresAt}
	if err := s.scopes.Save(ctx, grant); err != nil {
		return "", time.Time{}, err
	}
	return token, expiresAt, nil
}

func (s *VaultService) FetchCredential(ctx context.Context, scopeToken, callingProxyID string) (Delivered, error) {
	grant, err := s.scopes.ConsumeIfValid(ctx, scopeToken, callingProxyID)
	if err != nil {
		return Delivered{}, err
	}
	// The secret goes only with the target it is for (ADR-0039): no pin, no secret.
	account, err := s.accounts.Get(ctx, grant.PrivilegedAccountID)
	if err != nil {
		return Delivered{}, err
	}
	if account.HostKey == "" {
		return Delivered{}, ErrNoHostKey
	}
	version, err := s.secrets.CurrentVersion(ctx, grant.PrivilegedAccountID)
	if err != nil {
		return Delivered{}, err
	}
	plaintext, err := s.kms.Open(version.EncryptedMaterial)
	if err != nil {
		return Delivered{}, err
	}
	return Delivered{Type: "password", Material: plaintext, TargetHost: account.TargetHost, HostKey: account.HostKey}, nil
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

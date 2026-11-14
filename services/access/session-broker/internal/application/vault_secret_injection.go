package application

import (
	"context"
	"fmt"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const SecretInjectionScopeTTL = 15 * time.Second

// InjectVaultSecretWithStepUp is the complete control-plane orchestration for
// option A. The MFA grant is kept in this call: verify -> consume the grant -> mint a short-lived,
// one-use Vault scope -> send only the scope to the selected
// proxy. Secret bytes are fetched by that proxy directly from Vault.
func (s *SessionBrokerService) InjectVaultSecretWithStepUp(ctx context.Context, actorID string, actorRoles []string, sessionID string, proof MFAActionProof) error {
	binding, err := s.authorizedSecretAction(ctx, actorID, actorRoles, sessionID, "secret:inject")
	if err != nil {
		return err
	}
	if s.mfaAction == nil || s.vault == nil || s.proxy == nil {
		return fmt.Errorf("%w: secret injection dependencies are not configured", domain.ErrUnavailable)
	}

	grant, err := s.mfaAction.Verify(ctx, binding, proof)
	if err != nil {
		return fmt.Errorf("%w: verifying action step-up: %v", domain.ErrForbidden, err)
	}
	if grant.Grant == "" || grant.ExpiresIn <= 0 || grant.ExpiresIn > 30 {
		return fmt.Errorf("%w: authentication returned an invalid action grant", domain.ErrUnavailable)
	}

	// Re-read session state and policy after the MFA round-trip. A session that
	// expired, was terminated, or lost permission while the factor was checked
	// cannot proceed to scope issuance.
	currentBinding, err := s.authorizedSecretAction(ctx, actorID, actorRoles, sessionID, "secret:inject")
	if err != nil {
		return err
	}
	if currentBinding != binding {
		return domain.ErrForbidden
	}

	// Consume the action grant before minting the Vault scope. Any later failure
	// requires a fresh MFA ceremony; the grant can never be replayed.
	if err := s.mfaAction.Consume(ctx, binding, grant.Grant); err != nil {
		return fmt.Errorf("%w: consuming action grant: %v", domain.ErrForbidden, err)
	}
	grant.Grant = ""

	proxyServiceID, err := s.proxies.Select(binding.Protocol)
	if err != nil {
		return err
	}
	scopeToken, _, err := s.vault.AuthorizeScope(ctx, binding.SessionID, binding.AccountID, proxyServiceID, SecretInjectionScopeTTL)
	if err != nil {
		return fmt.Errorf("%w: authorizing one-use injection scope: %v", domain.ErrUnavailable, err)
	}
	if scopeToken == "" {
		return fmt.Errorf("%w: vault returned an empty injection scope", domain.ErrUnavailable)
	}

	if err := s.proxy.InjectVaultSecret(ctx, binding.Protocol, binding.SessionID, binding.AccountID, scopeToken); err != nil {
		return fmt.Errorf("%w: proxy rejected vault secret injection", domain.ErrUnavailable)
	}
	scopeToken = ""
	return nil
}

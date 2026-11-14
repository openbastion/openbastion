package application

import (
	"context"
	"errors"
	"fmt"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const (
	SecretInjectResourcePrefix = "secret:inject:account:"
	SecretPasteResourcePrefix  = "secret:paste:account:"
)

// StartSecretActionStepUp derives every binding field except action from the
// persisted session. Only its requester may use it; Authorization grants the
// distinct inject/paste capability for the exact account.
func (s *SessionBrokerService) StartSecretActionStepUp(ctx context.Context, actorID string, actorRoles []string, sessionID, action string) (MFAActionStart, error) {
	binding, err := s.authorizedSecretAction(ctx, actorID, actorRoles, sessionID, action)
	if err != nil {
		return MFAActionStart{}, err
	}
	if s.mfaAction == nil {
		return MFAActionStart{}, fmt.Errorf("%w: action step-up is not configured", domain.ErrUnavailable)
	}
	result, err := s.mfaAction.Start(ctx, binding)
	if err != nil {
		return MFAActionStart{}, fmt.Errorf("%w: starting action step-up: %v", domain.ErrUnavailable, err)
	}
	return result, nil
}

func (s *SessionBrokerService) authorizedSecretAction(ctx context.Context, actorID string, actorRoles []string, sessionID, action string) (MFAActionBinding, error) {
	if actorID == "" || sessionID == "" {
		return MFAActionBinding{}, domain.ErrForbidden
	}
	var resource string
	switch action {
	case "secret:inject":
		resource = SecretInjectResourcePrefix
	case "secret:paste":
		resource = SecretPasteResourcePrefix
	default:
		return MFAActionBinding{}, domain.ErrForbidden
	}
	sess, err := s.sessions.Get(ctx, sessionID)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			return MFAActionBinding{}, err
		}
		return MFAActionBinding{}, fmt.Errorf("%w: reading session for secret action: %v", domain.ErrUnavailable, err)
	}
	if actorID != sess.RequestedBy {
		return MFAActionBinding{}, domain.ErrForbidden
	}
	if sess.EffectiveStatus(s.clock()) != domain.StatusActive {
		return MFAActionBinding{}, fmt.Errorf("%w: secret action requires an active session", domain.ErrConflict)
	}
	if sess.Protocol != "ssh" {
		return MFAActionBinding{}, domain.ErrUnsupportedProtocol
	}
	allowed, _, err := s.authz.CheckAccess(ctx, actorRoles, resource+sess.PrivilegedAccountID, action)
	if err != nil {
		return MFAActionBinding{}, fmt.Errorf("%w: checking secret action permission: %v", domain.ErrUnavailable, err)
	}
	if !allowed {
		if auditErr := s.audit.EmitEvent(ctx, actorID, "session.secret_step_up", "session", sessionID, false); auditErr != nil {
			return MFAActionBinding{}, fmt.Errorf("%w: auditing refused secret action: %v", domain.ErrUnavailable, auditErr)
		}
		return MFAActionBinding{}, domain.ErrForbidden
	}
	return MFAActionBinding{ActorUserID: actorID, SessionID: sess.ID, AccountID: sess.PrivilegedAccountID, Protocol: sess.Protocol, Action: action}, nil
}

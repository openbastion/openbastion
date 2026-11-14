package application

import (
	"context"
	"crypto/sha256"
	"encoding/base64"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// ConsumeMFAActionGrant is reserved for the Session Broker. A grant is accepted
// only once, before expiry, and for the exact tuple it was issued for.
func (s *AuthenticationService) ConsumeMFAActionGrant(ctx context.Context, opaque string, expected domain.MFAActionGrantBinding) error {
	if s.mfaActions == nil {
		return ErrMFAActionStoreMissing
	}
	if expected.Validate() != nil {
		return ErrMFAActionRejected
	}
	raw, err := base64.RawURLEncoding.DecodeString(opaque)
	if err != nil || len(raw) != 32 {
		return ErrMFAActionRejected
	}
	hash := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}
	consumed, err := s.mfaActions.ConsumeActionGrant(ctx, hash[:], expected, s.clock())
	if err != nil {
		return err
	}
	if !consumed {
		return ErrMFAActionRejected
	}
	details := map[string]string{
		"account_id": expected.AccountID, "protocol": expected.Protocol, "action": expected.Action,
	}
	if err := s.recordWith(ctx, expected.UserID, ActionMFAActionGrantConsumed, "session", expected.SessionID, details); err != nil {
		return err
	}
	return nil
}

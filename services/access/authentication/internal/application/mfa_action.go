package application

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

const (
	MFAActionChallengeTTL = 2 * time.Minute
	MFAActionGrantTTL     = 30 * time.Second
	MFAActionMaxAttempts  = 5
)

var (
	ErrMFAActionRejected     = errors.New("the action's second factor was refused")
	ErrMFAActionNotEnrolled  = errors.New("the account has no eligible second factor")
	ErrMFAActionStoreMissing = errors.New("MFA action storage is not configured")
)

// MFAActionChallenge is safe to return to the Session Broker: it contains no
// credential, only the opaque challenge and the accepted factor names.
type MFAActionChallenge struct {
	Challenge string
	ExpiresIn time.Duration
	Factors   []string
	WebAuthn  []byte
}

// MFAActionGrant is the opaque one-time proof returned only to the Session Broker.
// It is bound in storage to one user/session/account/protocol/action tuple.
type MFAActionGrant struct {
	Grant     string
	ExpiresIn time.Duration
}

// WithMFAAction enables step-up ceremonies for privileged-session actions.
func (s *AuthenticationService) WithMFAAction(repo domain.MFAActionRepository) *AuthenticationService {
	s.mfaActions = repo
	return s
}

// StartMFAActionStepUp begins a fresh second-factor ceremony for exactly one action.
// The actor identity is supplied by the authenticated Session Broker over mTLS;
// it is never accepted from a public user route.
func (s *AuthenticationService) StartMFAActionStepUp(ctx context.Context, binding domain.MFAActionGrantBinding) (MFAActionChallenge, error) {
	if s.mfa == nil || s.sealer == nil || s.mfaActions == nil {
		return MFAActionChallenge{}, ErrMFAActionStoreMissing
	}
	if err := binding.Validate(); err != nil {
		return MFAActionChallenge{}, ErrMFAActionRejected
	}
	u, err := s.users.GetByID(ctx, binding.UserID)
	if err != nil {
		return MFAActionChallenge{}, ErrMFAActionRejected
	}

	sealed, _, err := s.mfa.TOTP(ctx, u.ID)
	if err != nil {
		return MFAActionChallenge{}, err
	}
	var keys []domain.WebAuthnCredential
	if s.webauthn != nil {
		keys, err = s.mfa.WebAuthnCredentials(ctx, u.ID)
		if err != nil {
			return MFAActionChallenge{}, err
		}
	}

	factors := make([]string, 0, 2)
	strict := s.strict(u.Roles)
	if !strict && len(sealed) > 0 {
		factors = append(factors, FactorTOTP)
	}
	if s.webauthn != nil && len(keys) > 0 {
		factors = append(factors, FactorWebAuthn)
	}
	if len(factors) == 0 {
		return MFAActionChallenge{}, ErrMFAActionNotEnrolled
	}

	var options []byte
	var webAuthnSession []byte
	if containsFactor(factors, FactorWebAuthn) {
		wu := WebAuthnUser{Handle: []byte(u.ID), Name: u.Username, Display: u.DisplayName, Keys: keys}
		options, webAuthnSession, err = s.webauthn.BeginLogin(wu)
		if err != nil {
			return MFAActionChallenge{}, err
		}
	}
	rawChallenge := make([]byte, 32)
	if _, err := rand.Read(rawChallenge); err != nil {
		return MFAActionChallenge{}, err
	}
	challenge := base64.RawURLEncoding.EncodeToString(rawChallenge)
	hash := sha256.Sum256(rawChallenge)
	for i := range rawChallenge {
		rawChallenge[i] = 0
	}

	now := s.clock()
	stored := domain.MFAActionChallenge{
		Hash: hash[:], Binding: binding, Factors: factors,
		WebAuthnSession: webAuthnSession, ExpiresAt: now.Add(MFAActionChallengeTTL),
	}
	if err := s.mfaActions.SaveActionChallenge(ctx, stored); err != nil {
		return MFAActionChallenge{}, err
	}
	details := map[string]string{
		"account_id": binding.AccountID, "protocol": binding.Protocol, "action": binding.Action,
	}
	if err := s.recordWith(ctx, binding.UserID, ActionMFAActionChallengeIssued, "session", binding.SessionID, details); err != nil {
		_, _ = s.mfaActions.ConsumeActionChallenge(ctx, hash[:], s.clock())
		return MFAActionChallenge{}, err
	}
	return MFAActionChallenge{Challenge: challenge, ExpiresIn: MFAActionChallengeTTL,
		Factors: append([]string(nil), factors...), WebAuthn: options}, nil
}

// VerifyMFAActionStepUp consumes a challenge and issues a short-lived, one-time grant.
// No login token is issued by this path.
func (s *AuthenticationService) VerifyMFAActionStepUp(ctx context.Context, challenge string, expected domain.MFAActionGrantBinding, factor, totpCode string, webAuthnResponse []byte) (MFAActionGrant, error) {
	if s.mfa == nil || s.sealer == nil || s.mfaActions == nil {
		return MFAActionGrant{}, ErrMFAActionStoreMissing
	}
	raw, err := base64.RawURLEncoding.DecodeString(challenge)
	if err != nil || len(raw) != 32 {
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	hash := sha256.Sum256(raw)
	for i := range raw {
		raw[i] = 0
	}
	if expected.Validate() != nil {
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	c, err := s.mfaActions.GetActionChallenge(ctx, hash[:])
	if errors.Is(err, domain.ErrChallengeNotFound) {
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	if err != nil {
		return MFAActionGrant{}, err
	}
	if c.Validate() != nil {
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	if c.Binding != expected {
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	now := s.clock()
	if !now.Before(c.ExpiresAt) {
		_, _ = s.mfaActions.ConsumeActionChallenge(ctx, hash[:], now)
		return MFAActionGrant{}, ErrMFAActionRejected
	}
	if !containsFactor(c.Factors, factor) {
		return MFAActionGrant{}, s.failMFAAction(ctx, c)
	}

	var verifiedKey *domain.WebAuthnCredential
	switch factor {
	case FactorTOTP:
		sealed, last, err := s.mfa.TOTP(ctx, c.Binding.UserID)
		if err != nil {
			return MFAActionGrant{}, err
		}
		if len(sealed) == 0 {
			return MFAActionGrant{}, s.failMFAAction(ctx, c)
		}
		secret, err := s.sealer.Open(c.Binding.UserID, sealed)
		if err != nil {
			return MFAActionGrant{}, fmt.Errorf("open TOTP secret: %w", err)
		}
		step, ok := matchTOTP(secret, totpCode, now, last)
		for i := range secret {
			secret[i] = 0
		}
		if !ok {
			return MFAActionGrant{}, s.failMFAAction(ctx, c)
		}
		// Reserve the challenge before advancing the account-wide TOTP step. A
		// concurrent replay on another challenge still loses the step CAS.
		consumed, err := s.mfaActions.ConsumeActionChallenge(ctx, hash[:], now)
		if err != nil {
			return MFAActionGrant{}, err
		}
		if !consumed {
			return MFAActionGrant{}, ErrMFAActionRejected
		}
		advanced, err := s.mfa.AdvanceTOTPStep(ctx, c.Binding.UserID, step)
		if err != nil {
			return MFAActionGrant{}, err
		}
		if !advanced {
			return MFAActionGrant{}, ErrMFAActionRejected
		}
	case FactorWebAuthn:
		if s.webauthn == nil || len(c.WebAuthnSession) == 0 {
			return MFAActionGrant{}, s.failMFAAction(ctx, c)
		}
		wu, _, err := s.webauthnUser(ctx, c.Binding.UserID)
		if err != nil {
			return MFAActionGrant{}, err
		}
		key, cloned, err := s.webauthn.FinishLogin(wu, c.WebAuthnSession, webAuthnResponse)
		if err != nil || cloned {
			return MFAActionGrant{}, s.failMFAAction(ctx, c)
		}
		verifiedKey = &key
	default:
		return MFAActionGrant{}, s.failMFAAction(ctx, c)
	}

	if factor == FactorWebAuthn {
		consumed, err := s.mfaActions.ConsumeActionChallenge(ctx, hash[:], now)
		if err != nil {
			return MFAActionGrant{}, err
		}
		if !consumed {
			return MFAActionGrant{}, ErrMFAActionRejected
		}
		verifiedKey.LastUsedAt = now
		if err := s.mfa.UpdateWebAuthnCredential(ctx, c.Binding.UserID, *verifiedKey); err != nil {
			return MFAActionGrant{}, err
		}
	}

	rawGrant := make([]byte, 32)
	if _, err := rand.Read(rawGrant); err != nil {
		return MFAActionGrant{}, err
	}
	grant := base64.RawURLEncoding.EncodeToString(rawGrant)
	grantHash := sha256.Sum256(rawGrant)
	for i := range rawGrant {
		rawGrant[i] = 0
	}
	if err := s.mfaActions.SaveActionGrant(ctx, domain.MFAActionGrant{
		Hash: grantHash[:], UserID: c.Binding.UserID, SessionID: c.Binding.SessionID,
		AccountID: c.Binding.AccountID, Protocol: c.Binding.Protocol, Action: c.Binding.Action,
		ExpiresAt: s.clock().Add(MFAActionGrantTTL),
	}); err != nil {
		return MFAActionGrant{}, err
	}
	details := map[string]string{
		"account_id": c.Binding.AccountID, "protocol": c.Binding.Protocol,
		"action": c.Binding.Action, "factor": factor,
	}
	if err := s.recordWith(ctx, c.Binding.UserID, ActionMFAActionVerified, "session", c.Binding.SessionID, details); err != nil {
		// The grant exists, but no authorization is returned if its audit cannot be
		// committed. Burn it so a later retry cannot turn an audit outage into access.
		_, _ = s.mfaActions.ConsumeActionGrant(ctx, grantHash[:], c.Binding, s.clock())
		return MFAActionGrant{}, err
	}
	return MFAActionGrant{Grant: grant, ExpiresIn: MFAActionGrantTTL}, nil
}

func (s *AuthenticationService) failMFAAction(ctx context.Context, c domain.MFAActionChallenge) error {
	_, err := s.mfaActions.FailActionChallenge(ctx, c.Hash, MFAActionMaxAttempts)
	if err != nil {
		return err
	}
	if s.audit != nil {
		details := map[string]string{
			"account_id": c.Binding.AccountID, "protocol": c.Binding.Protocol,
			"action": c.Binding.Action,
		}
		if err := s.emit(ctx, c.Binding.UserID, ActionMFAActionRefused, "session", c.Binding.SessionID, details, false); err != nil {
			log.Printf("authentication: refused MFA action could not be audited: %v", err)
		}
	}
	return ErrMFAActionRejected
}

func containsFactor(factors []string, factor string) bool {
	for _, candidate := range factors {
		if candidate == factor {
			return true
		}
	}
	return false
}

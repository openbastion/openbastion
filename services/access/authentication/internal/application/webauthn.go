package application

// WebAuthn, the second factor that resists phishing (ADR-0065): each signature is bound to the
// origin the browser saw. A second factor beside TOTP; for the roles declared strict, the only one
// that counts.

import (
	"context"
	"encoding/json"
	"log"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// MaxWebAuthnKeys bounds the security keys of one account.
const MaxWebAuthnKeys = 5

// The factors, as the challenge names them.
const (
	FactorTOTP     = "totp"
	FactorWebAuthn = "webauthn"
)

// WebAuthnUser is what a ceremony needs of an account.
type WebAuthnUser struct {
	Handle        []byte // the user handle: the account's id, never its name
	Name, Display string
	Keys          []domain.WebAuthnCredential
}

// WebAuthn is the port to the ceremonies' verifier. Options are what the browser is given;
// session is what must come back with the answer; response is the browser's answer as it sent it.
type WebAuthn interface {
	BeginLogin(u WebAuthnUser) (options json.RawMessage, session []byte, err error)
	// FinishLogin verifies the assertion — origin, rpId, user presence, challenge, signature by a key
	// of u — and returns the key as it is after it; cloned is true when its counter went back.
	FinishLogin(u WebAuthnUser, session, response []byte) (key domain.WebAuthnCredential, cloned bool, err error)
	BeginRegistration(u WebAuthnUser) (options json.RawMessage, session []byte, err error)
	FinishRegistration(u WebAuthnUser, session, response []byte) (domain.WebAuthnCredential, error)
}

// WithWebAuthn adds WebAuthn as a second factor; for strict roles, the only one that counts.
func (s *AuthenticationService) WithWebAuthn(w WebAuthn, strictRoles []string) *AuthenticationService {
	s.webauthn = w
	s.strictRoles = map[string]bool{}
	for _, r := range strictRoles {
		s.strictRoles[r] = true
	}
	return s
}

// strict says whether roles hold one for which only WebAuthn counts.
func (s *AuthenticationService) strict(roles []string) bool {
	for _, r := range roles {
		if s.strictRoles[r] {
			return true
		}
	}
	return false
}

func (s *AuthenticationService) webauthnUser(ctx context.Context, userID string) (WebAuthnUser, *domain.User, error) {
	u, err := s.users.GetByID(ctx, userID)
	if err != nil {
		return WebAuthnUser{}, nil, err
	}
	keys, err := s.mfa.WebAuthnCredentials(ctx, userID)
	if err != nil {
		return WebAuthnUser{}, nil, err
	}
	return WebAuthnUser{Handle: []byte(u.ID), Name: u.Username, Display: u.DisplayName, Keys: keys}, u, nil
}

// VerifyWebAuthn implements POST /auth/mfa/webauthn/verify: an assertion by a key of the account,
// for this challenge's ceremony, ends the login. A key whose counter went back is refused (a clone).
func (s *AuthenticationService) VerifyWebAuthn(ctx context.Context, challenge string, response []byte) (string, time.Duration, error) {
	c, err := s.liveChallenge(ctx, challenge, domain.MFAVerify)
	if err != nil {
		return "", 0, err
	}
	if s.webauthn == nil || c.WebAuthnSession == nil {
		return "", 0, s.fail(ctx, c)
	}
	wu, _, err := s.webauthnUser(ctx, c.UserID)
	if err != nil {
		return "", 0, err
	}
	key, cloned, err := s.webauthn.FinishLogin(wu, c.WebAuthnSession, response)
	if err != nil {
		return "", 0, s.fail(ctx, c)
	}
	if cloned {
		log.Printf("authentication: a security key of %q answered with a counter that went back: refused, as a clone would be", c.LoginName)
		return "", 0, s.fail(ctx, c)
	}
	if err := s.mfa.UpdateWebAuthnCredential(ctx, c.UserID, key); err != nil {
		return "", 0, err
	}
	return s.finish(ctx, c, ActionLoginWebAuthn)
}

// ConfirmWebAuthnEnrollment implements POST /auth/mfa/webauthn/enroll/confirm: the browser's new key,
// for the registration this challenge started, becomes the account's; the enrollment code is
// burned, the registration written to the audit first, and the login ends.
func (s *AuthenticationService) ConfirmWebAuthnEnrollment(ctx context.Context, challenge string, response []byte) (string, time.Duration, error) {
	c, err := s.liveChallenge(ctx, challenge, domain.MFAEnroll)
	if err != nil {
		return "", 0, err
	}
	if s.webauthn == nil || c.WebAuthnSession == nil {
		return "", 0, s.fail(ctx, c)
	}
	wu, u, err := s.webauthnUser(ctx, c.UserID)
	if err != nil {
		return "", 0, err
	}
	key, err := s.webauthn.FinishRegistration(wu, c.WebAuthnSession, response)
	if err != nil {
		return "", 0, s.fail(ctx, c)
	}
	key.CreatedAt = s.clock()
	took, err := s.mfa.TakeEnrollmentCode(ctx, c.LoginSource, c.LoginName, c.EnrollmentCodeHash, s.clock())
	if err != nil {
		return "", 0, err
	}
	if !took {
		_ = s.mfa.DeleteChallenge(ctx, c.Hash)
		return "", 0, ErrMFARejected
	}
	if err := s.record(ctx, u.ID, ActionMFAWebAuthnRegistered, "account", u.Username); err != nil {
		return "", 0, err
	}
	added, err := s.mfa.AddWebAuthnCredential(ctx, c.UserID, key, MaxWebAuthnKeys)
	if err != nil {
		return "", 0, err
	}
	if !added { // the account holds MaxWebAuthnKeys already, or the key is known
		_ = s.mfa.DeleteChallenge(ctx, c.Hash)
		return "", 0, ErrMFARejected
	}
	return s.finish(ctx, c, ActionLoginWebAuthn)
}

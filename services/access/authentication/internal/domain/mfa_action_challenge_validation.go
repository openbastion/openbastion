package domain

import "errors"

var ErrInvalidMFAActionChallenge = errors.New("invalid MFA action challenge")

// Validate rejects malformed challenges before they are persisted or verified.
func (c MFAActionChallenge) Validate() error {
	if len(c.Hash) != 32 || c.Binding.Validate() != nil || c.ExpiresAt.IsZero() ||
		len(c.Factors) == 0 || len(c.Factors) > 2 || c.Attempts < 0 {
		return ErrInvalidMFAActionChallenge
	}
	seen := map[string]bool{}
	for _, factor := range c.Factors {
		if (factor != "totp" && factor != "webauthn") || seen[factor] {
			return ErrInvalidMFAActionChallenge
		}
		seen[factor] = true
	}
	if seen["webauthn"] != (len(c.WebAuthnSession) > 0) {
		return ErrInvalidMFAActionChallenge
	}
	return nil
}

package domain

import "errors"

var ErrSecretInjectionOutcomeUnknown = errors.New("secret injection outcome unknown")

type SecretInjectionOutcomeUnknownError struct{ InjectionID string }

func (e *SecretInjectionOutcomeUnknownError) Error() string {
	return "secret injection outcome unknown; do not retry and verify the target"
}
func (e *SecretInjectionOutcomeUnknownError) Unwrap() error { return ErrSecretInjectionOutcomeUnknown }

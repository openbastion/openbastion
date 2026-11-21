package proxycore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

var (
	ErrSecretInjectionUnavailable    = errors.New("proxycore: secret injection unavailable")
	ErrSecretInjectionInvalid        = errors.New("proxycore: invalid secret injection")
	ErrSecretInjectionOutcomeUnknown = errors.New("proxycore: secret injection outcome unknown")
)

// SecretInjectionOutcomeUnknownError means the target write may have completed
// but its terminal audit acknowledgement did not. The operation id identifies
// the durable start/recording evidence; callers MUST NOT replay the secret.
type SecretInjectionOutcomeUnknownError struct{ InjectionID string }

func (e *SecretInjectionOutcomeUnknownError) Error() string {
	return "proxycore: secret injection outcome unknown; do not retry"
}
func (e *SecretInjectionOutcomeUnknownError) Unwrap() error { return ErrSecretInjectionOutcomeUnknown }

// SecretInputSource identifies where the bytes being typed came from. The source,
// never the bytes, is part of the evidence kept by the audit and recorder.
type SecretInputSource string

const (
	SecretInputVault    SecretInputSource = "vault"
	SecretInputOperator SecretInputSource = "operator"
)

// SecretInputEvidence is safe metadata about a secret input. Vault inputs retain
// only the account reference; operator-provided inputs retain their length and a
// salted SHA-256 (ADR-0133 §4, which refines ADR-0097 §6): SHA-256(salt || text),
// with a random salt per input kept next to it. Whoever holds a candidate value can
// still recognise it; a table computed in advance is of no use. It never contains
// the secret itself.
type SecretInputEvidence struct {
	SessionID   string
	InjectionID string // random per-attempt correlation id; never a credential or Vault scope
	Protocol    string
	Source      SecretInputSource
	AccountID   string
	Length      int
	SHA256      string // operator inputs: hex SHA-256(salt || text)
	Salt        string // operator inputs: hex of the 16 random bytes salting SHA256
	Timestamp   time.Time
}

// SecretTyper is the only protocol-specific part of secret injection. Implementations
// must type the complete byte sequence without using the clipboard, recorder, or logs.
type SecretTyper interface {
	TypeSecret(ctx context.Context, secret []byte) error
}

// SecretInputTransaction serializes the complete audit -> recording -> typing
// operation against ordinary operator input. A typer that cannot provide this
// guarantee must not be used for secret injection.
type SecretInputTransaction interface {
	WithExclusiveInput(ctx context.Context, operation func() error) error
}

// SecretInputAuditor writes a durable start event before target input and a
// completion/failure event after the target write attempt.
type SecretInputAuditor interface {
	AuditSecretInput(ctx context.Context, evidence SecretInputEvidence) error
	AuditSecretInputResult(ctx context.Context, evidence SecretInputEvidence, success bool) error
}

// SecretInputRecorder records a reference or fingerprint before the secret is sent.
type SecretInputRecorder interface {
	RecordSecretInput(ctx context.Context, evidence SecretInputEvidence) error
}

// SecretInputRegistrar exposes a live protocol input handle to the proxy's internal
// Session Broker route. Registrations are scoped to the relay lifetime and hold no secret bytes.
type SecretInputRegistrar interface {
	Register(ctx context.Context, sessionID, protocol, targetHost, targetUser string, typer SecretTyper, recorder SecretInputRecorder) func()
}

// InjectSecret enforces the shared ADR-0097 ordering for every protocol:
// audit, durable evidence, then typing. A missing or failed dependency refuses
// the operation. The caller's byte slice is zeroed on every return path.
func InjectSecret(
	ctx context.Context,
	sessionID, protocol string,
	source SecretInputSource,
	accountID string,
	secret []byte,
	auditor SecretInputAuditor,
	recorder SecretInputRecorder,
	typer SecretTyper,
) error {
	if secret != nil {
		defer zeroSecret(secret)
	}
	if ctx == nil || !safeSecretIdentifier(sessionID, 256) || !safeSecretIdentifier(protocol, 32) ||
		!safeSecretIdentifier(accountID, 128) || len(secret) == 0 || !utf8.Valid(secret) ||
		(source != SecretInputVault && source != SecretInputOperator) ||
		auditor == nil || recorder == nil || typer == nil {
		return ErrSecretInjectionInvalid
	}
	// Every source is a single credential line, never terminal input that could
	// execute a second command. Vault values are bounded independently of B's
	// stricter 128-rune operator-input contract.
	if len(secret) > 4096 {
		return ErrSecretInjectionInvalid
	}
	for remaining := secret; len(remaining) > 0; {
		r, size := utf8.DecodeRune(remaining)
		if size == 0 || r == utf8.RuneError && size == 1 || r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f {
			return ErrSecretInjectionInvalid
		}
		remaining = remaining[size:]
	}
	if source == SecretInputOperator && utf8.RuneCount(secret) > 128 {
		return ErrSecretInjectionInvalid
	}

	injectionID, err := newSecretInjectionID()
	if err != nil {
		return fmt.Errorf("%w: could not create injection correlation id", ErrSecretInjectionUnavailable)
	}
	evidence := SecretInputEvidence{
		SessionID: sessionID, InjectionID: injectionID,
		Protocol: protocol, Source: source, AccountID: accountID,
		Timestamp: time.Now().UTC(),
	}
	if source == SecretInputOperator {
		var salt [16]byte
		if _, err := rand.Read(salt[:]); err != nil {
			return fmt.Errorf("%w: could not salt the input's fingerprint", ErrSecretInjectionUnavailable)
		}
		evidence.Length = len(secret)
		evidence.SHA256 = SaltedSecretFingerprint(salt[:], secret)
		evidence.Salt = hex.EncodeToString(salt[:])
	}

	transaction, ok := typer.(SecretInputTransaction)
	if !ok {
		return ErrSecretInjectionInvalid
	}
	err = transaction.WithExclusiveInput(ctx, func() error {
		if err := auditor.AuditSecretInput(ctx, evidence); err != nil {
			return fmt.Errorf("%w: audit refused", ErrSecretInjectionUnavailable)
		}
		if err := recorder.RecordSecretInput(ctx, evidence); err != nil {
			if auditErr := auditSecretInputResult(auditor, ctx, evidence, false); auditErr != nil {
				return fmt.Errorf("%w: recording and result audit failed", ErrSecretInjectionUnavailable)
			}
			return fmt.Errorf("%w: recording refused", ErrSecretInjectionUnavailable)
		}
		if err := typer.TypeSecret(ctx, secret); err != nil {
			if auditErr := auditSecretInputResult(auditor, ctx, evidence, false); auditErr != nil {
				// A protocol typer can fail after writing a prefix. Without the
				// terminal audit acknowledgement the target state is also unknown.
				return &SecretInjectionOutcomeUnknownError{InjectionID: evidence.InjectionID}
			}
			return fmt.Errorf("%w: target input failed", ErrSecretInjectionUnavailable)
		}
		if err := auditSecretInputResult(auditor, ctx, evidence, true); err != nil {
			return &SecretInjectionOutcomeUnknownError{InjectionID: evidence.InjectionID}
		}
		return nil
	})
	return err
}

// safeSecretIdentifier accepts only short, printable identifiers that cannot
// inject terminal lines, log fields, or recording markers.
func safeSecretIdentifier(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':') {
			return false
		}
	}
	return true
}

// newSecretInjectionID creates a 128-bit random correlation id shared by the
// durable pre-audit event, recorder marker and terminal audit event. It lets
// auditors distinguish an unresolved attempt from a completed or failed one.
func newSecretInjectionID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func zeroSecret(secret []byte) {
	for i := range secret {
		secret[i] = 0
	}
}

// The result event must survive an HTTP caller disconnect or a session relay
// cancellation that happens after the target write attempt. It is bounded so a
// stalled audit service cannot hold the SSH input transaction indefinitely.
func auditSecretInputResult(auditor SecretInputAuditor, ctx context.Context, evidence SecretInputEvidence, success bool) error {
	resultCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	return auditor.AuditSecretInputResult(resultCtx, evidence, success)
}

// SaltedSecretFingerprint is the fingerprint an operator input leaves in the audit and the
// recording (ADR-0133 §4): hex SHA-256(salt || text). An auditor who holds a candidate value
// recognises it with the salt recorded next to it.
func SaltedSecretFingerprint(salt, text []byte) string {
	h := sha256.New()
	h.Write(salt)
	h.Write(text)
	return hex.EncodeToString(h.Sum(nil))
}

// validOperatorFingerprint checks an operator input's evidence: a length, a 64-hex fingerprint and
// a 32-hex salt.
func validOperatorFingerprint(evidence SecretInputEvidence) bool {
	if evidence.Length < 1 || len(evidence.SHA256) != 64 || len(evidence.Salt) != 32 {
		return false
	}
	if _, err := hex.DecodeString(evidence.SHA256); err != nil {
		return false
	}
	_, err := hex.DecodeString(evidence.Salt)
	return err == nil
}

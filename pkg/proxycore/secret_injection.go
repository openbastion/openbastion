package proxycore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"
	"unicode/utf8"
)

var (
	ErrSecretInjectionUnavailable = errors.New("proxycore: secret injection unavailable")
	ErrSecretInjectionInvalid     = errors.New("proxycore: invalid secret injection")
)

// SecretInputSource identifies where the bytes being typed came from. The source,
// never the bytes, is part of the evidence kept by the audit and recorder.
type SecretInputSource string

const (
	SecretInputVault    SecretInputSource = "vault"
	SecretInputOperator SecretInputSource = "operator"
)

// SecretInputEvidence is safe metadata about a secret input. Vault inputs retain
// only the account reference; operator-provided inputs retain length and SHA-256,
// as required by ADR-0097. It never contains the secret itself.
type SecretInputEvidence struct {
	SessionID string
	Protocol  string
	Source    SecretInputSource
	AccountID string
	Length    int
	SHA256    string
	Timestamp time.Time
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
	for _, r := range string(secret) {
		if r == '\r' || r == '\n' || r == '\t' || r < 0x20 || r == 0x7f {
			return ErrSecretInjectionInvalid
		}
	}
	if source == SecretInputOperator && utf8.RuneCount(secret) > 128 {
		return ErrSecretInjectionInvalid
	}

	evidence := SecretInputEvidence{
		SessionID: sessionID,
		Protocol:  protocol,
		Source:    source,
		AccountID: accountID,
		Timestamp: time.Now().UTC(),
	}
	if source == SecretInputOperator {
		evidence.Length = len(secret)
		sum := sha256.Sum256(secret)
		evidence.SHA256 = hex.EncodeToString(sum[:])
	}

	transaction, ok := typer.(SecretInputTransaction)
	if !ok {
		return ErrSecretInjectionInvalid
	}
	err := transaction.WithExclusiveInput(ctx, func() error {
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
				return fmt.Errorf("%w: target input and result audit failed", ErrSecretInjectionUnavailable)
			}
			return fmt.Errorf("%w: target input failed", ErrSecretInjectionUnavailable)
		}
		if err := auditSecretInputResult(auditor, ctx, evidence, true); err != nil {
			return fmt.Errorf("%w: result audit failed after target input", ErrSecretInjectionUnavailable)
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

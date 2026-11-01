package domain

// The second factor of ADR-0062: TOTP secrets, the challenges of a login in two steps, and the
// enrollment codes an administrator issues.

import (
	"context"
	"errors"
	"time"
)

// The kinds of challenge, as the client reads them.
const (
	MFAVerify = "required"            // the account has a secret: a code is asked
	MFAEnroll = "enrollment_required" // it has none: an administrator's enrollment code, then a code
)

// ErrChallengeNotFound: no challenge has this hash — never made, used, exhausted, or forged.
var ErrChallengeNotFound = errors.New("no such challenge")

// MFAChallenge is the second step of a login whose password was right. Its value is never kept:
// only its SHA-256.
type MFAChallenge struct {
	Hash                   []byte
	UserID                 string
	Roles                  []string // computed when the password was checked; the token gets them
	Kind                   string   // MFAVerify or MFAEnroll
	LoginSource, LoginName string   // what an enrollment code is issued for (ADR-0062 §4)
	PendingSecret          []byte   // enrollment: the secret given out, sealed, until a code confirms it
	EnrollmentCodeHash     []byte   // enrollment: the code that was shown, burned at the confirmation
	Attempts               int
	ExpiresAt              time.Time
}

// MFARepository keeps what the second factor needs.
type MFARepository interface {
	SaveChallenge(ctx context.Context, c MFAChallenge) error
	GetChallenge(ctx context.Context, hash []byte) (MFAChallenge, error)
	// FailChallenge counts one failed attempt; at max the challenge is deleted (gone is true).
	FailChallenge(ctx context.Context, hash []byte, max int) (gone bool, err error)
	// SetPendingSecret records the secret given out and the enrollment code shown, once: a
	// challenge that already has a pending secret is left as it is (false).
	SetPendingSecret(ctx context.Context, hash, sealed, codeHash []byte) (bool, error)
	DeleteChallenge(ctx context.Context, hash []byte) error

	// TOTP returns the account's sealed secret (nil if none) and the last step accepted.
	TOTP(ctx context.Context, userID string) (sealed []byte, lastStep int64, err error)
	// SetTOTP gives the account its secret, step being the one of the code that confirmed it.
	SetTOTP(ctx context.Context, userID string, sealed []byte, step int64) error
	// AdvanceTOTPStep takes step if it is after the last one accepted (compare-and-swap): a code
	// is used once, even by two logins at the same instant.
	AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error)
	ResetTOTP(ctx context.Context, userID string) error

	// PutEnrollmentCode keeps the code for source/name, replacing any earlier one.
	PutEnrollmentCode(ctx context.Context, source, name string, hash []byte, expiresAt time.Time) error
	// EnrollmentCodeMatches says whether hash is source/name's code, still valid.
	EnrollmentCodeMatches(ctx context.Context, source, name string, hash []byte, now time.Time) (bool, error)
	// TakeEnrollmentCode removes source/name's code if it is hash and still valid; false otherwise.
	TakeEnrollmentCode(ctx context.Context, source, name string, hash []byte, now time.Time) (bool, error)
}

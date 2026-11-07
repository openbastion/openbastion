package application

// The second factor (ADR-0062): an account that holds a declared role gets no token for its
// password alone. TOTP (RFC 6238: HMAC-SHA1, 30 s, 6 digits), each code used once; a secret is
// enrolled only with a one-time code an administrator issued.

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// SecretSealer seals TOTP secrets at rest, each bound to its account.
type SecretSealer interface {
	Seal(userID string, secret []byte) ([]byte, error)
	Open(userID string, sealed []byte) ([]byte, error)
}

const (
	ChallengeTTL         = 5 * time.Minute
	MaxChallengeAttempts = 5
	EnrollmentCodeTTL    = 24 * time.Hour
	totpPeriod           = 30 // seconds
	totpSkew             = 1  // steps on either side, for the clocks
	totpSecretBytes      = 20
)

var (
	// ErrMFARejected: the second step cannot be trusted — an unknown, expired or exhausted
	// challenge, a wrong or replayed code, an enrollment code that is not the one issued.
	ErrMFARejected = errors.New("the second factor was refused")
	// ErrMFAOff: no role requires a second factor.
	ErrMFAOff = errors.New("the second factor is not configured")
	// ErrUnknownAccount: an administrator named an account that does not exist.
	ErrUnknownAccount = errors.New("no such account")
)

// MFAChallengeRequired is what a login whose password was right says when a code is needed: not
// a token, a challenge for POST /auth/mfa/verify (or /auth/mfa/enroll).
type MFAChallengeRequired struct {
	Kind      string // domain.MFAVerify or domain.MFAEnroll
	Challenge string
	ExpiresIn time.Duration
	// Factors are those that may answer it (ADR-0065): to verify, those the account holds and its
	// roles accept; to enroll, those its roles accept. WebAuthn are the assertion options.
	Factors  []string
	WebAuthn json.RawMessage
}

func (e *MFAChallengeRequired) Error() string { return "a second factor is required: " + e.Kind }

// WithMFA turns the second factor on for the accounts that hold one of roles.
func (s *AuthenticationService) WithMFA(roles []string, repo domain.MFARepository, sealer SecretSealer) *AuthenticationService {
	s.mfaRoles = map[string]bool{}
	for _, r := range roles {
		s.mfaRoles[r] = true
	}
	s.mfa, s.sealer = repo, sealer
	return s
}

// mfaRequired says whether roles hold one that requires the second factor — a strict role does too.
func (s *AuthenticationService) mfaRequired(roles []string) bool {
	for _, r := range roles {
		if s.mfaRoles[r] {
			return true
		}
	}
	return s.strict(roles)
}

// tokenOrChallenge ends a login whose password was right: a token, or — when one of the roles
// requires it — a challenge, and no token.
func (s *AuthenticationService) tokenOrChallenge(ctx context.Context, u *domain.User, roles []string, source, loginName string) (string, time.Duration, error) {
	if s.mfa == nil || !s.mfaRequired(roles) {
		return s.issue(ctx, u, roles, ActionLogin)
	}
	sealed, _, err := s.mfa.TOTP(ctx, u.ID)
	if err != nil {
		return "", 0, err
	}
	var keys []domain.WebAuthnCredential
	if s.webauthn != nil {
		if keys, err = s.mfa.WebAuthnCredentials(ctx, u.ID); err != nil {
			return "", 0, err
		}
	}
	// What counts (ADR-0065): for a strict role, a security key only; otherwise TOTP, or a key.
	strict := s.strict(roles)
	accepted := []string{FactorWebAuthn}
	if !strict {
		accepted = []string{FactorTOTP}
		if s.webauthn != nil {
			accepted = append(accepted, FactorWebAuthn)
		}
	}
	var held []string
	if sealed != nil && !strict {
		held = append(held, FactorTOTP)
	}
	if len(keys) > 0 && s.webauthn != nil {
		held = append(held, FactorWebAuthn)
	}
	kind, factors := domain.MFAVerify, held
	if len(held) == 0 { // nothing the roles accept: enroll one, with an administrator's code
		kind, factors = domain.MFAEnroll, accepted
	}
	c := domain.MFAChallenge{UserID: u.ID, Roles: roles, Kind: kind, LoginSource: source, LoginName: loginName, ExpiresAt: s.clock().Add(ChallengeTTL)}
	var options json.RawMessage
	if kind == domain.MFAVerify && len(keys) > 0 && s.webauthn != nil {
		if options, c.WebAuthnSession, err = s.webauthn.BeginLogin(WebAuthnUser{Handle: []byte(u.ID), Name: u.Username, Display: u.DisplayName, Keys: keys}); err != nil {
			return "", 0, err
		}
	}
	challenge, err := random32()
	if err != nil {
		return "", 0, err
	}
	c.Hash = digest(challenge)
	if err := s.mfa.SaveChallenge(ctx, c); err != nil {
		return "", 0, err
	}
	return "", 0, &MFAChallengeRequired{Kind: kind, Challenge: challenge, ExpiresIn: ChallengeTTL, Factors: factors, WebAuthn: options}
}

// issue writes the login to the audit, then issues the token: no audit, no token (ADR-0064).
func (s *AuthenticationService) issue(ctx context.Context, u *domain.User, roles []string, action string) (string, time.Duration, error) {
	if err := s.record(ctx, u.ID, action, "account", u.Username); err != nil {
		return "", 0, err
	}
	token, err := s.tokens.Issue(u.ID, u.Username, roles, s.clock().Add(s.ttl))
	if err != nil {
		return "", 0, err
	}
	return token, s.ttl, nil
}

func digest(v string) []byte {
	h := sha256.Sum256([]byte(v))
	return h[:]
}

// liveChallenge is the challenge of value, of kind, not expired (an expired one is deleted).
func (s *AuthenticationService) liveChallenge(ctx context.Context, value, kind string) (domain.MFAChallenge, error) {
	if s.mfa == nil {
		return domain.MFAChallenge{}, ErrMFAOff
	}
	if value == "" || len(value) > 128 {
		return domain.MFAChallenge{}, ErrMFARejected
	}
	c, err := s.mfa.GetChallenge(ctx, digest(value))
	if errors.Is(err, domain.ErrChallengeNotFound) {
		return c, ErrMFARejected
	}
	if err != nil {
		return c, err
	}
	if !s.clock().Before(c.ExpiresAt) {
		_ = s.mfa.DeleteChallenge(ctx, c.Hash)
		return c, ErrMFARejected
	}
	if c.Kind != kind {
		return c, ErrMFARejected
	}
	return c, nil
}

// fail counts a failed attempt on c, writes the refusal (at best), and refuses.
func (s *AuthenticationService) fail(ctx context.Context, c domain.MFAChallenge) error {
	if _, err := s.mfa.FailChallenge(ctx, c.Hash, MaxChallengeAttempts); err != nil {
		return err
	}
	s.refused(ctx, c.LoginName)
	return ErrMFARejected
}

// VerifyMFA implements POST /auth/mfa/verify: the code of the account's secret, of a step not
// used before, ends the login.
func (s *AuthenticationService) VerifyMFA(ctx context.Context, challenge, code string) (string, time.Duration, error) {
	c, err := s.liveChallenge(ctx, challenge, domain.MFAVerify)
	if err != nil {
		return "", 0, err
	}
	if s.strict(c.Roles) { // a strict role: TOTP does not count (ADR-0065)
		return "", 0, s.fail(ctx, c)
	}
	sealed, last, err := s.mfa.TOTP(ctx, c.UserID)
	if err != nil {
		return "", 0, err
	}
	if sealed == nil { // reset since the password was checked
		_ = s.mfa.DeleteChallenge(ctx, c.Hash)
		return "", 0, ErrMFARejected
	}
	secret, err := s.sealer.Open(c.UserID, sealed)
	if err != nil {
		return "", 0, fmt.Errorf("the account's second factor cannot be opened: %w", err)
	}
	step, ok := matchTOTP(secret, code, s.clock(), last)
	if !ok {
		return "", 0, s.fail(ctx, c)
	}
	if took, err := s.mfa.AdvanceTOTPStep(ctx, c.UserID, step); err != nil {
		return "", 0, err
	} else if !took { // the same code, used at the same instant by another login
		return "", 0, s.fail(ctx, c)
	}
	return s.finish(ctx, c, ActionLoginMFA)
}

// finish deletes the challenge and issues the token, with the roles of the password's check.
func (s *AuthenticationService) finish(ctx context.Context, c domain.MFAChallenge, action string) (string, time.Duration, error) {
	if err := s.mfa.DeleteChallenge(ctx, c.Hash); err != nil {
		return "", 0, err
	}
	u, err := s.users.GetByID(ctx, c.UserID)
	if err != nil {
		return "", 0, err
	}
	return s.issue(ctx, u, c.Roles, action)
}

// Enrollment is what POST /auth/mfa/enroll gives out, once.
type Enrollment struct {
	Secret     string // base32, for an authenticator application
	OTPAuthURI string
	WebAuthn   json.RawMessage // the creation options, for a security key (ADR-0065)
}

// StartEnrollment implements POST /auth/mfa/enroll: with the enrollment code an administrator
// issued for this login name, the account gets a secret to enroll — not active until a code of it
// confirms it. Once per challenge.
func (s *AuthenticationService) StartEnrollment(ctx context.Context, challenge, enrollmentCode, factor string) (Enrollment, error) {
	c, err := s.liveChallenge(ctx, challenge, domain.MFAEnroll)
	if err != nil {
		return Enrollment{}, err
	}
	switch {
	case factor == "" || factor == FactorTOTP:
		if s.strict(c.Roles) { // a strict role enrolls a security key, not TOTP (ADR-0065)
			return Enrollment{}, s.fail(ctx, c)
		}
	case factor == FactorWebAuthn && s.webauthn != nil:
	default:
		return Enrollment{}, s.fail(ctx, c)
	}
	codeHash := digest(normalizeEnrollmentCode(enrollmentCode))
	ok, err := s.mfa.EnrollmentCodeMatches(ctx, c.LoginSource, c.LoginName, codeHash, s.clock())
	if err != nil {
		return Enrollment{}, err
	}
	if !ok {
		return Enrollment{}, s.fail(ctx, c)
	}
	if factor == FactorWebAuthn {
		wu, _, err := s.webauthnUser(ctx, c.UserID)
		if err != nil {
			return Enrollment{}, err
		}
		options, session, err := s.webauthn.BeginRegistration(wu)
		if err != nil {
			return Enrollment{}, err
		}
		set, err := s.mfa.SetPendingWebAuthn(ctx, c.Hash, session, codeHash)
		if err != nil {
			return Enrollment{}, err
		}
		if !set {
			return Enrollment{}, s.fail(ctx, c)
		}
		return Enrollment{WebAuthn: options}, nil
	}
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return Enrollment{}, err
	}
	sealed, err := s.sealer.Seal(c.UserID, secret)
	if err != nil {
		return Enrollment{}, err
	}
	set, err := s.mfa.SetPendingSecret(ctx, c.Hash, sealed, codeHash)
	if err != nil {
		return Enrollment{}, err
	}
	if !set { // a secret was already given out for this challenge
		return Enrollment{}, s.fail(ctx, c)
	}
	u, err := s.users.GetByID(ctx, c.UserID)
	if err != nil {
		return Enrollment{}, err
	}
	b32 := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret)
	label := url.PathEscape("OpenBastion:" + u.Username)
	uri := "otpauth://totp/" + label + "?" + url.Values{"secret": {b32}, "issuer": {"OpenBastion"}, "algorithm": {"SHA1"},
		"digits": {"6"}, "period": {"30"}}.Encode()
	return Enrollment{Secret: b32, OTPAuthURI: uri}, nil
}

// ConfirmEnrollment implements POST /auth/mfa/enroll/confirm: a code of the secret given out makes
// it the account's, burns the enrollment code, and ends the login.
func (s *AuthenticationService) ConfirmEnrollment(ctx context.Context, challenge, code string) (string, time.Duration, error) {
	c, err := s.liveChallenge(ctx, challenge, domain.MFAEnroll)
	if err != nil {
		return "", 0, err
	}
	if c.PendingSecret == nil {
		return "", 0, s.fail(ctx, c)
	}
	secret, err := s.sealer.Open(c.UserID, c.PendingSecret)
	if err != nil {
		return "", 0, err
	}
	step, ok := matchTOTP(secret, code, s.clock(), 0)
	if !ok {
		return "", 0, s.fail(ctx, c)
	}
	took, err := s.mfa.TakeEnrollmentCode(ctx, c.LoginSource, c.LoginName, c.EnrollmentCodeHash, s.clock())
	if err != nil {
		return "", 0, err
	}
	if !took { // used by another challenge, replaced by a newer code, or expired meanwhile
		_ = s.mfa.DeleteChallenge(ctx, c.Hash)
		return "", 0, ErrMFARejected
	}
	u, err := s.users.GetByID(ctx, c.UserID)
	if err != nil {
		return "", 0, err
	}
	// Written before the secret becomes the account's (ADR-0064).
	if err := s.record(ctx, u.ID, ActionMFAEnrolled, "account", u.Username); err != nil {
		return "", 0, err
	}
	if err := s.mfa.SetTOTP(ctx, c.UserID, c.PendingSecret, step); err != nil {
		return "", 0, err
	}
	return s.finish(ctx, c, ActionLoginMFA)
}

// IssueEnrollmentCode implements the administrator's `mfa enrollment-code`: a one-time code for
// source/loginName, valid EnrollmentCodeTTL, replacing any earlier one. The code is returned once
// and kept by its hash only.
func (s *AuthenticationService) IssueEnrollmentCode(ctx context.Context, actor, source, loginName string) (string, time.Time, error) {
	if s.mfa == nil {
		return "", time.Time{}, ErrMFAOff
	}
	switch source {
	case domain.SourceLocal:
		u, err := s.users.GetByUsername(ctx, loginName)
		if err != nil || (u.IdentitySource != "" && u.IdentitySource != domain.SourceLocal) {
			return "", time.Time{}, ErrUnknownAccount
		}
	default:
		// "ldap" (the directory of the LDAP_* variables, or the one that adopts the accounts made
		// before ADR-0076), or "ldap:<id>": a directory that is configured, never another (ADR-0076).
		if !strings.HasPrefix(source, domain.SourceLDAP) || (source != domain.SourceLDAP && !s.directoryBySource(source)) || !directoryUsername(loginName) {
			return "", time.Time{}, ErrUnknownAccount
		}
		loginName = strings.ToLower(loginName)
	}
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		return "", time.Time{}, err
	}
	code := strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(raw))
	expires := s.clock().Add(EnrollmentCodeTTL)
	// Written before the code exists (ADR-0064): no audit, no code.
	if err := s.record(ctx, actor, ActionMFACodeIssued, "account", source+":"+loginName); err != nil {
		return "", time.Time{}, err
	}
	if err := s.mfa.PutEnrollmentCode(ctx, source, loginName, digest(code), expires); err != nil {
		return "", time.Time{}, err
	}
	return code, expires, nil
}

// normalizeEnrollmentCode accepts the code as an administrator may have read it out: any case,
// with spaces or dashes.
func normalizeEnrollmentCode(c string) string {
	return strings.ToLower(strings.NewReplacer(" ", "", "-", "").Replace(strings.TrimSpace(c)))
}

// ResetMFA implements the administrator's `mfa reset`: the account's secret is forgotten; a new
// enrollment code is needed to enroll again.
func (s *AuthenticationService) ResetMFA(ctx context.Context, actor, username string) error {
	if s.mfa == nil {
		return ErrMFAOff
	}
	u, err := s.users.GetByUsername(ctx, username)
	if err != nil {
		return ErrUnknownAccount
	}
	// Written before the secret is forgotten (ADR-0064): no audit, no reset.
	if err := s.record(ctx, actor, ActionMFAReset, "account", u.Username); err != nil {
		return err
	}
	if err := s.mfa.ResetWebAuthn(ctx, u.ID); err != nil {
		return err
	}
	return s.mfa.ResetTOTP(ctx, u.ID)
}

// MFAEnabled says whether a role requires the second factor.
func (s *AuthenticationService) MFAEnabled() bool {
	return s.mfa != nil && (len(s.mfaRoles) > 0 || len(s.strictRoles) > 0)
}

// totpAt is the 6-digit code of secret at step (RFC 4226 §5.3, RFC 6238).
func totpAt(secret []byte, step int64) string {
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(step))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	sum := m.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	v := binary.BigEndian.Uint32(sum[off:off+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", v%1_000_000)
}

// matchTOTP finds the step, within the skew of now and after last, whose code is code. Each step
// is compared in constant time.
func matchTOTP(secret []byte, code string, now time.Time, last int64) (int64, bool) {
	if len(code) != 6 || strings.Trim(code, "0123456789") != "" {
		return 0, false
	}
	current := now.Unix() / totpPeriod
	found, ok := int64(0), false
	for step := current - totpSkew; step <= current+totpSkew; step++ {
		if subtle.ConstantTimeCompare([]byte(totpAt(secret, step)), []byte(code)) == 1 && step > last && !ok {
			found, ok = step, true
		}
	}
	return found, ok
}

// ParseRoleList reads a comma-separated list of role names, each once; empty is refused.
func ParseRoleList(v string) ([]string, error) {
	seen := map[string]bool{}
	var out []string
	for _, r := range strings.Split(v, ",") {
		r = strings.TrimSpace(r)
		if !validRole(r) {
			return nil, fmt.Errorf("%q is not a role name (a-z, 0-9, - and _)", r)
		}
		if !seen[r] {
			seen[r] = true
			out = append(out, r)
		}
	}
	return out, nil
}

package application_test

// The second factor (ADR-0062): no token for a declared role's password alone; a code used once;
// a secret enrolled only with an administrator's one-time code.

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/internal/infrastructure"
)

// code is RFC 6238 written again, apart from the service's: what an authenticator application
// shows for the base32 secret at t.
func code(t *testing.T, b32 string, at time.Time) string {
	t.Helper()
	secret, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	if err != nil {
		t.Fatal(err)
	}
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(at.Unix()/30))
	m := hmac.New(sha1.New, secret)
	m.Write(msg[:])
	s := m.Sum(nil)
	o := s[19] & 0xf
	return fmt.Sprintf("%06d", (binary.BigEndian.Uint32(s[o:o+4])&0x7fffffff)%1000000)
}

const mfaKey = "8f1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9"

type mfaWorld struct {
	svc    *application.AuthenticationService
	store  *infrastructure.InMemoryStore
	tokens *infrastructure.TokenIssuer
	now    *time.Time
	dir    *fakeDirectory
}

func mfaService(t *testing.T) *mfaWorld {
	t.Helper()
	key, _ := infrastructure.GenerateSigningKey()
	w := &mfaWorld{store: infrastructure.NewInMemoryStore(), tokens: infrastructure.NewTokenIssuer(key)}
	now := time.Now().UTC()
	w.now = &now
	sealer, err := infrastructure.NewMFASealer(mfaKey)
	if err != nil {
		t.Fatal(err)
	}
	w.dir = &fakeDirectory{user: "alice", password: "dir-pass", id: application.DirectoryIdentity{ID: "a1b2c3d4-0000-4000-8000-000000000001", Groups: []string{adminsDN}}}
	w.svc = application.NewAuthenticationService(w.store, infrastructure.Argon2Hasher{}, w.tokens, time.Hour).
		WithClock(func() time.Time { return *w.now }).
		WithDirectory(w.dir, application.RoleMap{adminsDN: {"platform-admin"}}).
		WithMFA([]string{"platform-admin", "vault-admin"}, w.store, sealer)
	ctx := context.Background()
	if _, err := w.svc.CreateUser(ctx, "root", "Root", "root-pass", []string{"platform-admin"}); err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.CreateUser(ctx, "dba", "DBA", "dba-pass", []string{"dba"}); err != nil {
		t.Fatal(err)
	}
	return w
}

// challenge logs in with the password and returns the challenge it must give.
func (w *mfaWorld) challenge(t *testing.T, user, password, kind string) string {
	t.Helper()
	token, _, err := w.svc.Login(context.Background(), user, password)
	var c *application.MFAChallengeRequired
	if token != "" || !errors.As(err, &c) || c.Kind != kind || c.Challenge == "" || c.ExpiresIn != 5*time.Minute {
		t.Fatalf("login %s: token %q, %v — want no token and a %q challenge of 5 min", user, token, err, kind)
	}
	return c.Challenge
}

// enroll takes root from no secret to an enrolled one, and returns the secret.
func (w *mfaWorld) enroll(t *testing.T) string {
	t.Helper()
	ctx := context.Background()
	ch := w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	ec, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	if err != nil {
		t.Fatal(err)
	}
	e, err := w.svc.StartEnrollment(ctx, ch, ec)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.ConfirmEnrollment(ctx, ch, code(t, e.Secret, *w.now)); err != nil {
		t.Fatal(err)
	}
	return e.Secret
}

func TestMFA_ADeclaredRoleGetsNoTokenForItsPasswordAlone_OthersAreUntouched(t *testing.T) {
	w := mfaService(t)
	w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	token, _, err := w.svc.Login(context.Background(), "dba", "dba-pass")
	if err != nil || token == "" {
		t.Fatalf("dba holds no declared role: %v", err)
	}
	// A wrong password is a refusal, not a challenge: the challenge tells a right password.
	if _, _, err := w.svc.Login(context.Background(), "root", "wrong"); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatalf("a wrong password: %v", err)
	}
}

func TestMFA_EnrollmentNeedsTheAdministratorsCode_ForThisAccount_Valid_Once(t *testing.T) {
	w := mfaService(t)
	ctx := context.Background()
	ch := w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	if _, err := w.svc.StartEnrollment(ctx, ch, "no-code-was-issued"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("no code issued: %v", err)
	}
	other, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "dba")
	if _, err := w.svc.StartEnrollment(ctx, ch, other); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("another account's code: %v", err)
	}
	stale, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	fresh, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	if _, err := w.svc.StartEnrollment(ctx, ch, stale); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a code replaced by a newer one: %v", err)
	}
	// Four failures so far: one more and the challenge is gone; a fresh one is needed.
	ch = w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	// The code as an administrator may read it out: upper case, in groups.
	spoken := strings.ToUpper(fresh[:4] + " " + fresh[4:12] + "-" + fresh[12:])
	e, err := w.svc.StartEnrollment(ctx, ch, spoken)
	if err != nil {
		t.Fatalf("the right code, read out: %v", err)
	}
	u, err := url.Parse(e.OTPAuthURI)
	if err != nil || u.Scheme != "otpauth" || u.Host != "totp" || u.Query().Get("secret") != e.Secret || u.Query().Get("issuer") != "OpenBastion" {
		t.Fatalf("otpauth URI %q", e.OTPAuthURI)
	}
	if _, err := w.svc.StartEnrollment(ctx, ch, fresh); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a second secret for the same challenge: %v", err)
	}
	if _, _, err := w.svc.ConfirmEnrollment(ctx, ch, "000000"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a wrong first code: %v", err)
	}
	token, _, err := w.svc.ConfirmEnrollment(ctx, ch, code(t, e.Secret, *w.now))
	if err != nil {
		t.Fatalf("confirm: %v", err)
	}
	_, username, roles, _, err := w.tokens.Verify(token)
	if err != nil || username != "root" || fmt.Sprint(roles) != "[platform-admin]" {
		t.Fatalf("token after enrollment: %s %v %v", username, roles, err)
	}
	// The account now asks for a code. Burned: even after a reset, the same code does not enroll.
	w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if err := w.svc.ResetMFA(ctx, "admin-cli", "root"); err != nil {
		t.Fatal(err)
	}
	ch = w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	if _, err := w.svc.StartEnrollment(ctx, ch, fresh); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("an enrollment code used twice: %v", err)
	}
}

func TestMFA_ACodeIsUsedOnce_WithinOneStepEitherSide_AndFiveFailuresEndTheChallenge(t *testing.T) {
	w := mfaService(t)
	ctx := context.Background()
	secret := w.enroll(t)
	// The enrollment spent its step (S); two steps later, S+1 is one step old and unused.
	*w.now = w.now.Add(60 * time.Second)

	ch := w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, w.now.Add(-90*time.Second))); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a code three steps old: %v", err)
	}
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, w.now.Add(-60*time.Second))); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the enrollment's code, two steps old and spent: %v", err)
	}
	c := code(t, secret, w.now.Add(-30*time.Second))
	token, _, err := w.svc.VerifyMFA(ctx, ch, c)
	if err != nil || token == "" {
		t.Fatalf("a code one step old: %v", err)
	}
	// The same code again, on a new challenge: replayed.
	ch = w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if _, _, err := w.svc.VerifyMFA(ctx, ch, c); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a replayed code: %v", err)
	}
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, *w.now)); err != nil {
		t.Fatalf("the current code after a replayed one: %v", err)
	}
	// A challenge does not verify an enrollment, and the reverse.
	ch = w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if _, err := w.svc.StartEnrollment(ctx, ch, "x"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("an enrollment on a verify challenge: %v", err)
	}
	for i := 0; i < application.MaxChallengeAttempts; i++ {
		if _, _, err := w.svc.VerifyMFA(ctx, ch, "000000"); !errors.Is(err, application.ErrMFARejected) {
			t.Fatalf("wrong code %d: %v", i+1, err)
		}
	}
	*w.now = w.now.Add(30 * time.Second)
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, *w.now)); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the right code after five failures: %v, want the challenge gone", err)
	}
	// Expired.
	ch = w.challenge(t, "root", "root-pass", domain.MFAVerify)
	*w.now = w.now.Add(5*time.Minute + time.Second)
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, *w.now)); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("an expired challenge: %v", err)
	}
	for _, bad := range []string{"", "not-a-challenge", strings.Repeat("x", 200)} {
		if _, _, err := w.svc.VerifyMFA(ctx, bad, code(t, secret, *w.now)); !errors.Is(err, application.ErrMFARejected) {
			t.Fatalf("challenge %q: %v", bad, err)
		}
	}
}

// An enrolled account cannot be enrolled again, even with a valid enrollment code: the second
// factor would be replaced by whoever holds the password, without the first device. Reset first.
func TestMFA_AnEnrolledAccountCannotBeReEnrolled_EvenWithAValidCode(t *testing.T) {
	w := mfaService(t)
	ctx := context.Background()
	w.enroll(t)
	ec, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	if err != nil {
		t.Fatal(err)
	}
	ch := w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if _, err := w.svc.StartEnrollment(ctx, ch, ec); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a new secret for an enrolled account: %v", err)
	}
	if _, _, err := w.svc.ConfirmEnrollment(ctx, ch, "123456"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a confirmation on a verify challenge: %v", err)
	}
}

func TestMFA_TheSecretIsSealedForItsAccount_AndAResetAsksForANewEnrollment(t *testing.T) {
	w := mfaService(t)
	ctx := context.Background()
	b32 := w.enroll(t)
	raw, _ := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(b32)
	root, _ := w.store.GetByUsername(ctx, "root")
	sealed, _, _ := w.store.TOTP(ctx, root.ID)
	if len(sealed) == 0 || bytes.Contains(sealed, raw) || bytes.Contains(sealed, []byte(b32)) {
		t.Fatalf("the secret is kept readable: %x", sealed)
	}
	sealer, _ := infrastructure.NewMFASealer(mfaKey)
	if _, err := sealer.Open("user_other", sealed); err == nil {
		t.Fatal("a sealed secret opens for another account")
	}
	other, _ := infrastructure.NewMFASealer(strings.Repeat("ab", 32))
	if _, err := other.Open(root.ID, sealed); err == nil {
		t.Fatal("a sealed secret opens with another key")
	}

	ch := w.challenge(t, "root", "root-pass", domain.MFAVerify)
	if err := w.svc.ResetMFA(ctx, "admin-cli", "root"); err != nil {
		t.Fatal(err)
	}
	*w.now = w.now.Add(30 * time.Second)
	if _, _, err := w.svc.VerifyMFA(ctx, ch, code(t, b32, *w.now)); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a code of the reset secret: %v", err)
	}
	w.challenge(t, "root", "root-pass", domain.MFAEnroll)
	if err := w.svc.ResetMFA(ctx, "admin-cli", "nobody"); !errors.Is(err, application.ErrUnknownAccount) {
		t.Fatalf("reset of an unknown account: %v", err)
	}
}

func TestMFA_ADirectoryAccountEnrollsWithTheCodeOfItsLoginName(t *testing.T) {
	w := mfaService(t)
	ctx := context.Background()
	_, _, err := w.svc.LoginLDAP(ctx, "alice", "dir-pass")
	var c *application.MFAChallengeRequired
	if !errors.As(err, &c) || c.Kind != domain.MFAEnroll {
		t.Fatalf("a directory admin: %v, want an enrollment challenge", err)
	}
	// The account ldap:<id> exists only now; the administrator names the login, in any case.
	ec, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLDAP, "ALICE")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "ldap:"+w.dir.id.ID); !errors.Is(err, application.ErrUnknownAccount) {
		t.Fatalf("a local code for a directory account: %v", err)
	}
	e, err := w.svc.StartEnrollment(ctx, c.Challenge, ec)
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	token, _, err := w.svc.ConfirmEnrollment(ctx, c.Challenge, code(t, e.Secret, *w.now))
	if err != nil {
		t.Fatal(err)
	}
	_, username, roles, _, _ := w.tokens.Verify(token)
	if username != "ldap:"+w.dir.id.ID || fmt.Sprint(roles) != "[platform-admin]" {
		t.Fatalf("token %s %v", username, roles)
	}
	// A local code does not enroll the directory login of the same name, nor the reverse.
	if _, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "nobody"); !errors.Is(err, application.ErrUnknownAccount) {
		t.Fatalf("a local code for no account: %v", err)
	}
}

func TestParseRoleList_RefusesWhatIsNotARoleName(t *testing.T) {
	if r, err := application.ParseRoleList(" platform-admin, vault-admin,platform-admin"); err != nil || fmt.Sprint(r) != "[platform-admin vault-admin]" {
		t.Fatalf("%v %v", r, err)
	}
	for _, bad := range []string{"", "a,,b", "Platform Admin", "admin;drop"} {
		if _, err := application.ParseRoleList(bad); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}

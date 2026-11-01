package application_test

// ADR-0065: WebAuthn beside TOTP; for a strict role, the only factor that counts.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// fakeWebAuthn signs nothing: an answer is accepted when it names the ceremony's session and a key
// of the user, as the real verifier would after its checks. cloned makes the next login say the
// counter went back.
type fakeWebAuthn struct {
	n      int
	cloned bool
}

func (f *fakeWebAuthn) BeginLogin(u application.WebAuthnUser) (json.RawMessage, []byte, error) {
	f.n++
	return json.RawMessage(`{"publicKey":{"challenge":"c"}}`), []byte(fmt.Sprintf("login-%d-%s", f.n, u.Handle)), nil
}

func (f *fakeWebAuthn) FinishLogin(u application.WebAuthnUser, session, response []byte) (domain.WebAuthnCredential, bool, error) {
	var r struct{ Session, Key string }
	if json.Unmarshal(response, &r) != nil || r.Session != string(session) {
		return domain.WebAuthnCredential{}, false, errors.New("assertion does not verify")
	}
	for _, k := range u.Keys {
		if string(k.ID) == r.Key {
			k.SignCount++
			return k, f.cloned, nil
		}
	}
	return domain.WebAuthnCredential{}, false, errors.New("not a key of this user")
}

func (f *fakeWebAuthn) BeginRegistration(u application.WebAuthnUser) (json.RawMessage, []byte, error) {
	f.n++
	return json.RawMessage(`{"publicKey":{"rp":{"id":"bastion.example"}}}`), []byte(fmt.Sprintf("reg-%d-%s", f.n, u.Handle)), nil
}

func (f *fakeWebAuthn) FinishRegistration(u application.WebAuthnUser, session, response []byte) (domain.WebAuthnCredential, error) {
	var r struct{ Session, Key string }
	if json.Unmarshal(response, &r) != nil || r.Session != string(session) {
		return domain.WebAuthnCredential{}, errors.New("attestation does not verify")
	}
	return domain.WebAuthnCredential{ID: []byte(r.Key), Data: []byte(`{}`)}, nil
}

func answer(session []byte, key string) []byte {
	b, _ := json.Marshal(map[string]string{"Session": string(session), "Key": key})
	return b
}

// strictWorld: root is platform-admin, a strict role; dba holds a role that requires a factor.
func strictWorld(t *testing.T) (*mfaWorld, *fakeWebAuthn) {
	t.Helper()
	w := mfaService(t)
	f := &fakeWebAuthn{}
	w.svc.WithWebAuthn(f, []string{"platform-admin"})
	w.svc.WithMFA([]string{"vault-admin", "dba"}, w.store, mustSealer(t))
	return w, f
}

func loginChallenge(t *testing.T, w *mfaWorld, user, pw string) *application.MFAChallengeRequired {
	t.Helper()
	_, _, err := w.svc.Login(context.Background(), user, pw)
	var c *application.MFAChallengeRequired
	if !errors.As(err, &c) {
		t.Fatalf("login %s: %v, want a challenge", user, err)
	}
	return c
}

// enrollKey enrolls a security key for user through its enrollment challenge.
func enrollKey(t *testing.T, w *mfaWorld, f *fakeWebAuthn, user, pw, key string) string {
	t.Helper()
	ctx := context.Background()
	c := loginChallenge(t, w, user, pw)
	ec, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, user)
	if err != nil {
		t.Fatal(err)
	}
	e, err := w.svc.StartEnrollment(ctx, c.Challenge, ec, application.FactorWebAuthn)
	if err != nil || len(e.WebAuthn) == 0 || e.Secret != "" {
		t.Fatalf("start a key's enrollment: %+v %v", e, err)
	}
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	if _, _, err := w.svc.ConfirmWebAuthnEnrollment(ctx, c.Challenge, answer(ch.WebAuthnSession, key)); err != nil {
		t.Fatalf("confirm the key: %v", err)
	}
	return ec
}

func TestWebAuthn_AStrictRoleCanOnlyEnrollAKey_AndOnlyAKeyGivesItAToken(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	c := loginChallenge(t, w, "root", "root-pass")
	if c.Kind != domain.MFAEnroll || fmt.Sprint(c.Factors) != "[webauthn]" {
		t.Fatalf("a strict role with nothing: %s %v, want an enrollment of webauthn only", c.Kind, c.Factors)
	}
	ec, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	if _, err := w.svc.StartEnrollment(ctx, c.Challenge, ec, application.FactorTOTP); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("TOTP for a strict role: %v", err)
	}
	enrollKey(t, w, f, "root", "root-pass", "key-1")

	c = loginChallenge(t, w, "root", "root-pass")
	if c.Kind != domain.MFAVerify || fmt.Sprint(c.Factors) != "[webauthn]" || len(c.WebAuthn) == 0 {
		t.Fatalf("a strict role with a key: %s %v %s", c.Kind, c.Factors, c.WebAuthn)
	}
	if _, _, err := w.svc.VerifyMFA(ctx, c.Challenge, "123456"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a TOTP code for a strict role: %v", err)
	}
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	if _, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-2")); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a key of no one: %v", err)
	}
	token, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"))
	if err != nil || token == "" {
		t.Fatalf("the account's key: %v", err)
	}
	// The challenge is spent.
	if _, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1")); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a spent challenge: %v", err)
	}
}

func TestWebAuthn_AStrictRoleWithOnlyTOTPMustEnrollAKey(t *testing.T) {
	w := mfaService(t) // platform-admin requires a second factor; TOTP is all there is
	w.enroll(t)
	if c := loginChallenge(t, w, "root", "root-pass"); c.Kind != domain.MFAVerify || fmt.Sprint(c.Factors) != "[totp]" {
		t.Fatalf("before WebAuthn: %s %v", c.Kind, c.Factors)
	}
	w.svc.WithWebAuthn(&fakeWebAuthn{}, []string{"platform-admin"}) // then the role becomes strict
	c := loginChallenge(t, w, "root", "root-pass")
	if c.Kind != domain.MFAEnroll || fmt.Sprint(c.Factors) != "[webauthn]" {
		t.Fatalf("a strict role holding TOTP only: %s %v, want an enrollment of a key", c.Kind, c.Factors)
	}
}

func TestWebAuthn_AKeyWhoseCounterWentBackIsRefused_AndAResetForgetsTheKeys(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	f.cloned = true
	c := loginChallenge(t, w, "root", "root-pass")
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	if _, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1")); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a cloned key: %v", err)
	}
	f.cloned = false
	root, _ := w.store.GetByUsername(ctx, "root")
	if err := w.svc.ResetMFA(ctx, "admin-cli", "root"); err != nil {
		t.Fatal(err)
	}
	if keys, _ := w.store.WebAuthnCredentials(ctx, root.ID); len(keys) != 0 {
		t.Fatalf("keys after a reset: %d", len(keys))
	}
	if c := loginChallenge(t, w, "root", "root-pass"); c.Kind != domain.MFAEnroll {
		t.Fatalf("after a reset: %s", c.Kind)
	}
}

func TestWebAuthn_TheEnrollmentCodeOfAKeyIsBurned(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	ec := enrollKey(t, w, f, "root", "root-pass", "key-1")
	if err := w.svc.ResetMFA(ctx, "admin-cli", "root"); err != nil {
		t.Fatal(err)
	}
	c := loginChallenge(t, w, "root", "root-pass")
	if _, err := w.svc.StartEnrollment(ctx, c.Challenge, ec, application.FactorWebAuthn); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the code of an enrolled key, used again: %v", err)
	}
}

func TestWebAuthn_ANonStrictRoleMayUseEitherFactor_AndAnEnrolledAccountIsNotReEnrolled(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	c := loginChallenge(t, w, "dba", "dba-pass")
	if c.Kind != domain.MFAEnroll || fmt.Sprint(c.Factors) != "[totp webauthn]" {
		t.Fatalf("a non-strict role: %s %v", c.Kind, c.Factors)
	}
	enrollKey(t, w, f, "dba", "dba-pass", "dba-key")
	c = loginChallenge(t, w, "dba", "dba-pass")
	if c.Kind != domain.MFAVerify || fmt.Sprint(c.Factors) != "[webauthn]" {
		t.Fatalf("after enrolling a key: %s %v", c.Kind, c.Factors)
	}
	// Enrolled: a valid enrollment code adds nothing on a verify challenge.
	ec, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "dba")
	if _, err := w.svc.StartEnrollment(ctx, c.Challenge, ec, application.FactorWebAuthn); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a key added to an enrolled account through its login: %v", err)
	}
	// A factor that is not one, or WebAuthn where it is not configured.
	c2 := loginChallenge(t, mfaWorldWithout(t), "root", "root-pass")
	if _, err := w.svc.StartEnrollment(ctx, c2.Challenge, ec, "sms"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("an unknown factor: %v", err)
	}
}

func TestWebAuthn_NoMoreThanFiveKeys(t *testing.T) {
	w, _ := strictWorld(t)
	ctx := context.Background()
	root, _ := w.store.GetByUsername(ctx, "root")
	for i := 0; i < application.MaxWebAuthnKeys; i++ {
		if ok, _ := w.store.AddWebAuthnCredential(ctx, root.ID, domain.WebAuthnCredential{ID: []byte(fmt.Sprint("k", i)), Data: []byte("{}")}, application.MaxWebAuthnKeys); !ok {
			t.Fatalf("key %d refused", i)
		}
	}
	if ok, _ := w.store.AddWebAuthnCredential(ctx, root.ID, domain.WebAuthnCredential{ID: []byte("k-extra"), Data: []byte("{}")}, application.MaxWebAuthnKeys); ok {
		t.Fatal("a sixth key kept")
	}
}

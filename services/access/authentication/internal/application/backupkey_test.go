package application_test

// ADR-0066: one more key needs both the current key's signature and an administrator's code;
// an administrator lists and revokes one key, written to the audit first.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// addKey adds key to user with the signature of current, and returns the token of the login.
func addKey(t *testing.T, w *mfaWorld, user, pw, current, key string) (string, error) {
	t.Helper()
	ctx := context.Background()
	c := loginChallenge(t, w, user, pw)
	ec, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, user)
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	options, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, current), ec)
	if err != nil {
		return "", err
	}
	if len(options) == 0 {
		t.Fatal("no creation options")
	}
	ch, _ = w.store.GetChallenge(ctx, hashOf(c.Challenge))
	token, _, err := w.svc.ConfirmWebAuthnEnrollment(ctx, c.Challenge, answer(ch.WebAuthnSession, key))
	return token, err
}

// keyLogin logs user in with key.
func keyLogin(t *testing.T, w *mfaWorld, user, pw, key string) error {
	t.Helper()
	ctx := context.Background()
	c := loginChallenge(t, w, user, pw)
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	_, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, key))
	return err
}

func TestBackupKey_TheCurrentKeyAndAnAdministratorsCodeAddOne_AndEitherKeyLogsIn(t *testing.T) {
	w, f := strictWorld(t)
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	if token, err := addKey(t, w, "root", "root-pass", "key-1", "key-2"); err != nil || token == "" {
		t.Fatalf("add a key: %v", err)
	}
	for _, k := range []string{"key-1", "key-2"} {
		if err := keyLogin(t, w, "root", "root-pass", k); err != nil {
			t.Fatalf("login with %s: %v", k, err)
		}
	}
}

func TestBackupKey_EitherProofAloneIsRefused_AndTheChallengeOfAnAdditionDoesNotLogIn(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	c := loginChallenge(t, w, "root", "root-pass")
	ch, _ := w.store.GetChallenge(ctx, hashOf(c.Challenge))
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"), "not-issued"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the signature without a code: %v", err)
	}
	dbaCode, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "dba")
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"), dbaCode); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("another account's code: %v", err)
	}
	ec, _, _ := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "root")
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-of-no-one"), ec); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the code without the current key's signature: %v", err)
	}
	f.cloned = true
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"), ec); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a cloned key: %v", err)
	}
	f.cloned = false
	// Four failures; the fifth try, right, converts the challenge — which then no longer logs in.
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"), ec); err != nil {
		t.Fatalf("both proofs: %v", err)
	}
	if _, _, err := w.svc.VerifyWebAuthn(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1")); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the challenge of an addition used to log in: %v", err)
	}
	if _, err := w.svc.AddWebAuthnKey(ctx, c.Challenge, answer(ch.WebAuthnSession, "key-1"), ec); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("an addition started twice: %v", err)
	}
}

func TestBackupKey_NoMoreThanFiveKeys(t *testing.T) {
	w, f := strictWorld(t)
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	for i := 2; i <= application.MaxWebAuthnKeys; i++ {
		if _, err := addKey(t, w, "root", "root-pass", "key-1", fmt.Sprint("key-", i)); err != nil {
			t.Fatalf("key %d: %v", i, err)
		}
	}
	if _, err := addKey(t, w, "root", "root-pass", "key-1", "key-6"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("a sixth key: %v", err)
	}
}

func TestBackupKey_AnAdministratorListsAndRevokesOneKey_WrittenFirst_TheOtherStays(t *testing.T) {
	w, f := strictWorld(t)
	ctx := context.Background()
	a := &fakeAudit{}
	w.svc.WithAudit(a, nil)
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	if _, err := addKey(t, w, "root", "root-pass", "key-1", "key-2"); err != nil {
		t.Fatal(err)
	}
	keys, _ := w.svc.WebAuthnKeys(ctx, "root")
	if len(keys) != 2 || !keys[1].LastUsedAt.IsZero() {
		t.Fatalf("the backup key, never used yet: %+v", keys)
	}
	if err := keyLogin(t, w, "root", "root-pass", "key-2"); err != nil {
		t.Fatal(err)
	}
	keys, err := w.svc.WebAuthnKeys(ctx, "root")
	if err != nil || len(keys) != 2 || string(keys[0].ID) != "key-1" || keys[1].LastUsedAt.IsZero() || keys[1].CreatedAt.IsZero() {
		t.Fatalf("keys after a login with the backup key: %+v %v", keys, err)
	}
	a.down = true
	if err := w.svc.RevokeWebAuthnKey(ctx, "admin-cli", "root", []byte("key-1")); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("a revocation with the audit down: %v", err)
	}
	if keys, _ := w.svc.WebAuthnKeys(ctx, "root"); len(keys) != 2 { // a login would be refused too: the audit is down
		t.Fatalf("revoked without the audit: %d keys left", len(keys))
	}
	a.down = false
	if err := w.svc.RevokeWebAuthnKey(ctx, "admin-cli", "root", []byte("key-1")); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(a.actions(), "auth.mfa_webauthn_revoked:root/a2V5LTE") {
		t.Fatalf("events %s", a.actions())
	}
	if err := keyLogin(t, w, "root", "root-pass", "key-1"); !errors.Is(err, application.ErrMFARejected) {
		t.Fatalf("the revoked key: %v", err)
	}
	if err := keyLogin(t, w, "root", "root-pass", "key-2"); err != nil {
		t.Fatalf("the other key: %v", err)
	}
	if err := w.svc.RevokeWebAuthnKey(ctx, "admin-cli", "root", []byte("key-1")); !errors.Is(err, application.ErrUnknownKey) {
		t.Fatalf("a key revoked twice: %v", err)
	}
	if _, err := w.svc.WebAuthnKeys(ctx, "nobody"); !errors.Is(err, application.ErrUnknownAccount) {
		t.Fatalf("keys of no one: %v", err)
	}
}

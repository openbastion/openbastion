package application_test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

func actionBinding() domain.MFAActionGrantBinding {
	return domain.MFAActionGrantBinding{
		UserID: "user_root", SessionID: "session-01", AccountID: "account-01",
		Protocol: "ssh", Action: "secret:inject",
	}
}

func TestMFAActionStepUp_TOTPProducesOnlyBoundSingleUseActionGrant(t *testing.T) {
	w := mfaService(t)
	secret := w.enroll(t)
	*w.now = w.now.Add(30 * time.Second)
	u, err := w.store.GetByUsername(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	binding := actionBinding()
	binding.UserID = u.ID
	started, err := w.svc.StartMFAActionStepUp(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if started.ExpiresIn != application.MFAActionChallengeTTL || len(started.Factors) != 1 || started.Factors[0] != application.FactorTOTP {
		t.Fatalf("unexpected challenge: %+v", started)
	}
	wrongBinding := binding
	wrongBinding.SessionID = "another-session"
	if _, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, wrongBinding, application.FactorTOTP, code(t, secret, *w.now), nil); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("challenge accepted for another session: %v", err)
	}
	grant, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, application.FactorTOTP, code(t, secret, *w.now), nil)
	if err != nil || grant.Grant == "" || grant.ExpiresIn != application.MFAActionGrantTTL {
		t.Fatalf("step-up: %+v %v", grant, err)
	}
	if _, _, _, _, err := w.tokens.Verify(grant.Grant); err == nil {
		t.Fatal("an action grant was accepted as a login token")
	}

	raw, err := base64.RawURLEncoding.DecodeString(grant.Grant)
	if err != nil || len(raw) != 32 {
		t.Fatalf("opaque grant encoding: %v", err)
	}
	for i := range raw {
		raw[i] = 0
	}

	wrong := binding
	wrong.SessionID = "another-session"
	if err := w.svc.ConsumeMFAActionGrant(context.Background(), grant.Grant, wrong); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("grant escaped its session: %v", err)
	}
	if err := w.svc.ConsumeMFAActionGrant(context.Background(), grant.Grant, binding); err != nil {
		t.Fatalf("valid grant: %v", err)
	}
	if err := w.svc.ConsumeMFAActionGrant(context.Background(), grant.Grant, binding); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("grant replay: %v", err)
	}
	if _, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, application.FactorTOTP, code(t, secret, *w.now), nil); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("challenge replay: %v", err)
	}
}

func TestMFAActionStepUp_StrictRoleRequiresWebAuthn(t *testing.T) {
	w, f := strictWorld(t)
	enrollKey(t, w, f, "root", "root-pass", "key-1")
	u, err := w.store.GetByUsername(context.Background(), "root")
	if err != nil {
		t.Fatal(err)
	}
	binding := actionBinding()
	binding.UserID = u.ID
	started, err := w.svc.StartMFAActionStepUp(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if len(started.Factors) != 1 || started.Factors[0] != application.FactorWebAuthn || len(started.WebAuthn) == 0 {
		t.Fatalf("strict role received a weaker factor: %+v", started)
	}
	raw, err := base64.RawURLEncoding.DecodeString(started.Challenge)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256(raw)
	stored, err := w.store.GetActionChallenge(context.Background(), hash[:])
	if err != nil {
		t.Fatal(err)
	}
	grant, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, application.FactorWebAuthn, "", answer(stored.WebAuthnSession, "key-1"))
	if err != nil || grant.Grant == "" {
		t.Fatalf("WebAuthn step-up: %+v %v", grant, err)
	}
}

func TestMFAActionStepUp_RequiresEnrolledFactorAndRejectsInvalidContext(t *testing.T) {
	w := mfaService(t)
	dba, err := w.store.GetByUsername(context.Background(), "dba")
	if err != nil {
		t.Fatal(err)
	}
	binding := actionBinding()
	binding.UserID = dba.ID
	if _, err := w.svc.StartMFAActionStepUp(context.Background(), binding); !errors.Is(err, application.ErrMFAActionNotEnrolled) {
		t.Fatalf("account without factor: %v", err)
	}
	binding.Protocol = "telnet"
	if _, err := w.svc.StartMFAActionStepUp(context.Background(), binding); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("unsupported protocol: %v", err)
	}
}

func TestMFAActionStepUp_ExpiredChallengeAndWrongFactorAreRefused(t *testing.T) {
	w := mfaService(t)
	secret := w.enroll(t)
	u, _ := w.store.GetByUsername(context.Background(), "root")
	binding := actionBinding()
	binding.UserID = u.ID
	started, err := w.svc.StartMFAActionStepUp(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, "sms", "123456", nil); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("unsupported factor: %v", err)
	}
	*w.now = w.now.Add(application.MFAActionChallengeTTL + time.Second)
	if _, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, application.FactorTOTP, code(t, secret, *w.now), nil); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("expired challenge: %v", err)
	}
}

type failingActionAudit struct{}

func (failingActionAudit) EmitEvent(context.Context, string, string, string, string, bool) error {
	return errors.New("audit unavailable")
}

func TestMFAActionStepUp_AuditFailureNeverReturnsChallengeOrGrant(t *testing.T) {
	w := mfaService(t)
	w.enroll(t)
	u, _ := w.store.GetByUsername(context.Background(), "root")
	w.svc.WithAudit(failingActionAudit{}, nil)
	binding := actionBinding()
	binding.UserID = u.ID
	if _, err := w.svc.StartMFAActionStepUp(context.Background(), binding); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("challenge returned without audit: %v", err)
	}
}

func TestMFAActionGrant_AuditFailureBurnsGrantWithoutAuthorizingAction(t *testing.T) {
	w := mfaService(t)
	secret := w.enroll(t)
	*w.now = w.now.Add(30 * time.Second)
	u, _ := w.store.GetByUsername(context.Background(), "root")
	binding := actionBinding()
	binding.UserID = u.ID
	started, err := w.svc.StartMFAActionStepUp(context.Background(), binding)
	if err != nil {
		t.Fatal(err)
	}
	grant, err := w.svc.VerifyMFAActionStepUp(context.Background(), started.Challenge, binding, application.FactorTOTP, code(t, secret, *w.now), nil)
	if err != nil {
		t.Fatal(err)
	}

	w.svc.WithAudit(failingActionAudit{}, nil)
	if err := w.svc.ConsumeMFAActionGrant(context.Background(), grant.Grant, binding); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("grant consumed without required audit: %v", err)
	}
	w.svc.WithAudit(nil, nil)
	if err := w.svc.ConsumeMFAActionGrant(context.Background(), grant.Grant, binding); !errors.Is(err, application.ErrMFAActionRejected) {
		t.Fatalf("grant survived audit failure and could authorize later: %v", err)
	}
}

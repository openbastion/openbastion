package application_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type fakeMFAActionClient struct {
	start          application.MFAActionStart
	grant          application.MFAActionGrant
	startBinding   application.MFAActionBinding
	verifyBinding  application.MFAActionBinding
	consumeBinding application.MFAActionBinding
	consumedGrant  string
	proof          application.MFAActionProof
	startErr       error
	verifyErr      error
	onVerify       func()
}

func (f *fakeMFAActionClient) Start(_ context.Context, b application.MFAActionBinding) (application.MFAActionStart, error) {
	f.startBinding = b
	return f.start, f.startErr
}
func (f *fakeMFAActionClient) Verify(_ context.Context, b application.MFAActionBinding, p application.MFAActionProof) (application.MFAActionGrant, error) {
	f.verifyBinding = b
	f.proof = p
	if f.onVerify != nil {
		f.onVerify()
	}
	return f.grant, f.verifyErr
}
func (f *fakeMFAActionClient) Consume(_ context.Context, b application.MFAActionBinding, grant string) error {
	f.consumeBinding = b
	f.consumedGrant = grant
	return nil
}

func TestSecretActionStepUp_BindsToStoredSessionAndChecksAuthorization(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	audit := &fakeAudit{}
	broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "acc1", "ssh", "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &fakeMFAActionClient{start: application.MFAActionStart{Challenge: "challenge", ExpiresIn: 120, Factors: []string{"totp"}}, grant: application.MFAActionGrant{Grant: "opaque", ExpiresIn: 30}}
	broker.WithMFAActionClient(mfa)

	started, err := broker.StartSecretActionStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, "secret:inject")
	if err != nil || started.Challenge != "challenge" {
		t.Fatalf("start=%+v err=%v", started, err)
	}
	want := application.MFAActionBinding{ActorUserID: "user1", SessionID: sess.ID, AccountID: "acc1", Protocol: "ssh", Action: "secret:inject"}
	if mfa.startBinding != want {
		t.Fatalf("start binding=%+v want=%+v", mfa.startBinding, want)
	}
	if len(authz.asked) == 0 || authz.asked[len(authz.asked)-1] != "secret:inject secret:inject:account:acc1" {
		t.Fatalf("authorization did not check the exact account/action: %v", authz.asked)
	}

}

func TestSecretActionStepUp_RejectsNonOwnerDeniedPolicyAndInactiveSession(t *testing.T) {
	t.Run("non owner", func(t *testing.T) {
		authz := &fakeAuthz{allowed: true}
		audit := &fakeAudit{}
		broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)
		sess, err := broker.CreateSession(context.Background(), "owner", []string{"dba"}, "acc1", "ssh", "incident", "", 30)
		if err != nil {
			t.Fatal(err)
		}
		mfa := &fakeMFAActionClient{}
		broker.WithMFAActionClient(mfa)
		_, err = broker.StartSecretActionStepUp(context.Background(), "other", []string{"dba"}, sess.ID, "secret:inject")
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("non-owner err=%v", err)
		}
		if mfa.startBinding.ActorUserID != "" {
			t.Fatal("MFA called for non-owner")
		}
	})
	t.Run("policy denied", func(t *testing.T) {
		authz := &fakeAuthz{allowed: true, byResource: map[string]bool{"secret:inject:account:acc1": false}}
		audit := &fakeAudit{}
		broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)
		sess, err := broker.CreateSession(context.Background(), "owner", []string{"dba"}, "acc1", "ssh", "incident", "", 30)
		if err != nil {
			t.Fatal(err)
		}
		mfa := &fakeMFAActionClient{}
		broker.WithMFAActionClient(mfa)
		_, err = broker.StartSecretActionStepUp(context.Background(), "owner", []string{"dba"}, sess.ID, "secret:inject")
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("policy denial err=%v", err)
		}
		if mfa.startBinding.ActorUserID != "" {
			t.Fatal("MFA called after Authorization denied")
		}
		if len(audit.events) == 0 || audit.events[len(audit.events)-1] != "session.secret_step_up" {
			t.Fatalf("refusal not audited: %v", audit.events)
		}
	})
	t.Run("expired", func(t *testing.T) {
		authz := &fakeAuthz{allowed: true}
		audit := &fakeAudit{}
		broker := newDefaultTestBroker(authz, &fakeVaultAuthorizer{}, audit)
		now := time.Now().UTC()
		sess, err := broker.CreateSession(context.Background(), "owner", []string{"dba"}, "acc1", "ssh", "incident", "", 1)
		if err != nil {
			t.Fatal(err)
		}
		mfa := &fakeMFAActionClient{}
		broker.WithMFAActionClient(mfa).WithClock(func() time.Time { return now.Add(2 * time.Minute) })
		_, err = broker.StartSecretActionStepUp(context.Background(), "owner", []string{"dba"}, sess.ID, "secret:inject")
		if !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("expired session err=%v", err)
		}
		if mfa.startBinding.ActorUserID != "" {
			t.Fatal("MFA called for expired session")
		}
	})
}

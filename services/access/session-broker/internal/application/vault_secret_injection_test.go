package application_test

import (
	"context"
	"errors"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

func TestInjectVaultSecretWithStepUp_KeepsGrantAndSecretOutOfGatewayAndBrokerProxyPayload(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{scopeToken: "one-use-proxy-scope"}
	proxy := &fakeProxyClient{}
	broker := newTestBroker(authz, vault, &fakeAudit{}, &fakeAccountLookup{}, proxy)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", "ssh", "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "opaque-action-grant", ExpiresIn: 30}}
	broker.WithMFAActionClient(mfa)

	proof := application.MFAActionProof{Challenge: "challenge", Factor: "totp", TOTPCode: "123456"}
	if err := broker.InjectVaultSecretWithStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, proof); err != nil {
		t.Fatal(err)
	}

	want := application.MFAActionBinding{ActorUserID: "user1", SessionID: sess.ID, AccountID: "account-1", Protocol: "ssh", Action: "secret:inject"}
	if mfa.verifyBinding != want || mfa.consumeBinding != want || mfa.consumedGrant != "opaque-action-grant" {
		t.Fatalf("MFA verify/consume mismatch: verify=%+v consume=%+v", mfa.verifyBinding, mfa.consumeBinding)
	}
	if vault.calls != 1 || vault.lastProxyID != "ssh-proxy" {
		t.Fatalf("Vault scope not bound to SSH proxy: %+v", vault)
	}
	if proxy.injectCalls != 1 || proxy.lastInjectSession != sess.ID || proxy.lastInjectAccount != "account-1" || proxy.lastInjectScope != "one-use-proxy-scope" {
		t.Fatalf("proxy injection payload mismatch: %+v", proxy)
	}
}

func TestInjectVaultSecretWithStepUp_FailsClosedBeforeProxyWhenMFAConsumptionFails(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{scopeToken: "one-use-proxy-scope"}
	proxy := &fakeProxyClient{}
	broker := newTestBroker(authz, vault, &fakeAudit{}, &fakeAccountLookup{}, proxy)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", "ssh", "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &failingConsumeMFA{fakeMFAActionClient: fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "grant", ExpiresIn: 30}}}
	broker.WithMFAActionClient(mfa)
	err = broker.InjectVaultSecretWithStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, application.MFAActionProof{Challenge: "challenge", Factor: "totp", TOTPCode: "123456"})
	if err == nil {
		t.Fatal("expected consume failure")
	}
	if proxy.injectCalls != 0 || vault.calls != 0 {
		t.Fatal("Vault or proxy called after MFA grant consumption failed")
	}
}

type failingConsumeMFA struct{ fakeMFAActionClient }

func (f *failingConsumeMFA) Consume(context.Context, application.MFAActionBinding, string) error {
	return context.DeadlineExceeded
}

func TestInjectVaultSecretWithStepUp_RefusesProtocolWithoutRegisteredTyper(t *testing.T) {
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{scopeToken: "scope"}
	proxy := &fakeProxyClient{}
	broker := newTestBroker(authz, vault, &fakeAudit{}, &fakeAccountLookup{protocol: "vnc"}, proxy)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", "vnc", "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "grant", ExpiresIn: 30}}
	broker.WithMFAActionClient(mfa)
	err = broker.InjectVaultSecretWithStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, application.MFAActionProof{Challenge: "challenge", Factor: "totp", TOTPCode: "123456"})
	if !errors.Is(err, domain.ErrUnsupportedProtocol) {
		t.Fatalf("err=%v", err)
	}
	if mfa.verifyBinding.ActorUserID != "" || vault.calls != 0 || proxy.injectCalls != 0 {
		t.Fatal("unsupported protocol reached MFA, Vault or proxy")
	}
}

func TestInjectVaultSecretWithStepUp_RechecksAuthorizationAfterMFA(t *testing.T) {
	resource := "secret:inject:account:account-1"
	authz := &fakeAuthz{allowed: true}
	vault := &fakeVaultAuthorizer{scopeToken: "scope"}
	proxy := &fakeProxyClient{}
	broker := newTestBroker(authz, vault, &fakeAudit{}, &fakeAccountLookup{}, proxy)
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", "ssh", "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "grant", ExpiresIn: 30}}
	mfa.onVerify = func() { authz.byResource = map[string]bool{resource: false} }
	broker.WithMFAActionClient(mfa)
	err = broker.InjectVaultSecretWithStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, application.MFAActionProof{Challenge: "challenge", Factor: "totp", TOTPCode: "123456"})
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err=%v", err)
	}
	if vault.calls != 0 || proxy.injectCalls != 0 || mfa.consumedGrant != "" {
		t.Fatal("authorization loss after MFA reached Vault, consumed grant or proxy")
	}
}

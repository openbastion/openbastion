package application_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

type fakePasteProxy struct {
	calls                             int
	protocol, session, account, token string
	ttl                               time.Duration
	err                               error
}

func (p *fakePasteProxy) AuthorizePaste(_ context.Context, protocol, sessionID, accountID, token string, ttl time.Duration) error {
	p.calls++
	p.protocol, p.session, p.account, p.token, p.ttl = protocol, sessionID, accountID, token, ttl
	return p.err
}

func pasteBroker(t *testing.T, protocol string, audit *fakeAudit) (*application.SessionBrokerService, string, *fakeAuthz, *fakeMFAActionClient, *fakePasteProxy) {
	t.Helper()
	authz := &fakeAuthz{allowed: true}
	broker := newTestBroker(authz, &fakeVaultAuthorizer{scopeToken: "scope"}, audit, &fakeAccountLookup{protocol: protocol}, &fakeProxyClient{})
	sess, err := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", protocol, "incident", "", 30)
	if err != nil {
		t.Fatal(err)
	}
	mfa := &fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "grant", ExpiresIn: 30}}
	proxy := &fakePasteProxy{}
	broker.WithMFAActionClient(mfa).WithPasteProxy(proxy)
	return broker, sess.ID, authz, mfa, proxy
}

var pasteProof = application.MFAActionProof{Challenge: "challenge", Factor: "totp", TOTPCode: "123456"}

// ADR-0133 §2: after the second factor for secret:paste on the session's account, the grant is
// consumed, a one-use token goes to the screen proxy, the paste is audited, and the browser gets the
// same token; the Broker never sees a text.
func TestAuthorizeOperatorPaste_TheFactorThenTheToken(t *testing.T) {
	for _, protocol := range []string{"vnc", "rdp"} {
		t.Run(protocol, func(t *testing.T) {
			audit := &fakeAudit{}
			broker, sessionID, _, mfa, proxy := pasteBroker(t, protocol, audit)
			grant, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sessionID, pasteProof)
			if err != nil {
				t.Fatal(err)
			}
			want := application.MFAActionBinding{ActorUserID: "user1", SessionID: sessionID, AccountID: "account-1", Protocol: protocol, Action: "secret:paste"}
			if mfa.verifyBinding != want || mfa.consumeBinding != want || mfa.consumedGrant != "grant" {
				t.Fatalf("binding: verify %+v consume %+v", mfa.verifyBinding, mfa.consumeBinding)
			}
			raw, err := hex.DecodeString(grant.Token)
			if err != nil || len(raw) != 32 || grant.ExpiresInSeconds != 60 {
				t.Fatalf("grant %+v", grant)
			}
			if proxy.calls != 1 || proxy.token != grant.Token || proxy.session != sessionID || proxy.account != "account-1" || proxy.protocol != protocol || proxy.ttl != time.Minute {
				t.Fatalf("proxy %+v", proxy)
			}
			if audit.events[len(audit.events)-1] != "session.secret_paste_authorized" {
				t.Fatalf("audit %v", audit.events)
			}
		})
	}
}

func TestAuthorizeOperatorPaste_RefusesWhatItMustNotGrant(t *testing.T) {
	t.Run("SSH has no screen stream to carry it", func(t *testing.T) {
		broker, sessionID, _, mfa, proxy := pasteBroker(t, "ssh", &fakeAudit{})
		if _, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sessionID, pasteProof); !errors.Is(err, domain.ErrUnsupportedProtocol) || proxy.calls != 0 || mfa.consumedGrant != "" {
			t.Fatalf("%v, proxy %d", err, proxy.calls)
		}
	})
	t.Run("another user", func(t *testing.T) {
		broker, sessionID, _, _, proxy := pasteBroker(t, "vnc", &fakeAudit{})
		if _, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user2", []string{"dba"}, sessionID, pasteProof); !errors.Is(err, domain.ErrForbidden) || proxy.calls != 0 {
			t.Fatalf("%v", err)
		}
	})
	t.Run("the right withdrawn while the factor was checked", func(t *testing.T) {
		broker, sessionID, authz, mfa, proxy := pasteBroker(t, "rdp", &fakeAudit{})
		mfa.onVerify = func() { authz.byResource = map[string]bool{"secret:paste:account:account-1": false} }
		if _, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sessionID, pasteProof); !errors.Is(err, domain.ErrForbidden) || proxy.calls != 0 || mfa.consumedGrant != "" {
			t.Fatalf("%v, proxy %d, consumed %q", err, proxy.calls, mfa.consumedGrant)
		}
	})
	t.Run("the proxy refuses the token", func(t *testing.T) {
		broker, sessionID, _, _, proxy := pasteBroker(t, "vnc", &fakeAudit{})
		proxy.err = errors.New("session input is not active")
		if grant, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sessionID, pasteProof); !errors.Is(err, domain.ErrUnavailable) || grant.Token != "" {
			t.Fatalf("%+v, %v", grant, err)
		}
	})
	t.Run("without the audit, the browser gets nothing", func(t *testing.T) {
		audit := &fakeAudit{}
		broker, sessionID, _, _, _ := pasteBroker(t, "vnc", audit)
		audit.failing = true
		if grant, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sessionID, pasteProof); err == nil || grant.Token != "" {
			t.Fatalf("%+v, %v", grant, err)
		}
	})
	t.Run("no paste proxy", func(t *testing.T) {
		authz := &fakeAuthz{allowed: true}
		broker := newTestBroker(authz, &fakeVaultAuthorizer{scopeToken: "scope"}, &fakeAudit{}, &fakeAccountLookup{protocol: "vnc"}, &fakeProxyClient{})
		sess, _ := broker.CreateSession(context.Background(), "user1", []string{"dba"}, "account-1", "vnc", "incident", "", 30)
		broker.WithMFAActionClient(&fakeMFAActionClient{grant: application.MFAActionGrant{Grant: "grant", ExpiresIn: 30}})
		if _, err := broker.AuthorizeOperatorPasteWithStepUp(context.Background(), "user1", []string{"dba"}, sess.ID, pasteProof); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("%v", err)
		}
	})
}

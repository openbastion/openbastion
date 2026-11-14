package interfaces_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/interfaces"
)

type stepUpMFA struct {
	startBinding  application.MFAActionBinding
	verifyBinding application.MFAActionBinding
	proof         application.MFAActionProof
	consumed      string
	verifyErr     error
}

func (m *stepUpMFA) Start(_ context.Context, binding application.MFAActionBinding) (application.MFAActionStart, error) {
	m.startBinding = binding
	return application.MFAActionStart{Challenge: "challenge-opaque", ExpiresIn: 120, Factors: []string{"totp"}}, nil
}

func (m *stepUpMFA) Verify(_ context.Context, binding application.MFAActionBinding, proof application.MFAActionProof) (application.MFAActionGrant, error) {
	m.verifyBinding, m.proof = binding, proof
	if m.verifyErr != nil {
		return application.MFAActionGrant{}, m.verifyErr
	}
	return application.MFAActionGrant{Grant: "grant-must-not-leave-broker", ExpiresIn: 30}, nil
}

func (m *stepUpMFA) Consume(_ context.Context, binding application.MFAActionBinding, grant string) error {
	if binding != m.verifyBinding {
		return errors.New("grant binding changed")
	}
	m.consumed = grant
	return nil
}

type secretInjectionProxy struct {
	injectedSession string
	injectedAccount string
	injectedScope   string
}

func (p *secretInjectionProxy) EstablishSession(context.Context, string, string, string, string, string, time.Duration, bool, domain.ClipboardRights) (string, string, error) {
	return "https://ssh-proxy.example", "connection-ticket", nil
}
func (p *secretInjectionProxy) RevokeSession(context.Context, string, string, time.Duration) error {
	return nil
}
func (p *secretInjectionProxy) InjectVaultSecret(_ context.Context, _, sessionID, accountID, scope string) error {
	p.injectedSession, p.injectedAccount, p.injectedScope = sessionID, accountID, scope
	return nil
}

func newSecretInjectionServer(t *testing.T, mfa *stepUpMFA, proxy *secretInjectionProxy) (*application.SessionBrokerService, http.Handler, *domain.Session) {
	t.Helper()
	svc := application.NewSessionBrokerService(infrastructure.NewInMemoryStore(), allowAuthz{}, okVault{}, quietAudit{}, oneAccount{}, proxy).
		WithMFAActionClient(mfa)
	sess, err := svc.CreateSession(context.Background(), "alice", []string{"dba"}, "account-42", "ssh", "incident", "", 20)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return svc, interfaces.NewHTTPServer(svc).Routes(), sess
}

func TestSecretInjectionStepUp_ReturnsOnlyChallengeAndIsNoStore(t *testing.T) {
	mfa, proxy := &stepUpMFA{}, &secretInjectionProxy{}
	_, handler, sess := newSecretInjectionServer(t, mfa, proxy)
	req := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/secret-injection-step-up", strings.NewReader(`{"callerId":"alice","actorRoles":["dba"]}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK || rec.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("got %d, Cache-Control=%q, body=%s", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["challenge"] != "challenge-opaque" || got["expires_in"] != float64(120) {
		t.Fatalf("unexpected challenge response: %#v", got)
	}
	if _, ok := got["grant"]; ok {
		t.Fatalf("grant leaked in challenge response: %#v", got)
	}
	want := application.MFAActionBinding{ActorUserID: "alice", SessionID: sess.ID, AccountID: "account-42", Protocol: "ssh", Action: "secret:inject"}
	if mfa.startBinding != want {
		t.Fatalf("MFA binding = %+v, want %+v", mfa.startBinding, want)
	}
	if proxy.injectedScope != "" {
		t.Fatal("starting MFA unexpectedly injected a secret")
	}
}

func TestSecretInjection_VerifiesConsumesAndReturnsNoGrantOrScope(t *testing.T) {
	mfa, proxy := &stepUpMFA{}, &secretInjectionProxy{}
	_, handler, sess := newSecretInjectionServer(t, mfa, proxy)
	body := `{"callerId":"alice","actorRoles":["dba"],"challenge":"challenge-opaque","factor":"totp","totp_code":"123456"}`
	req := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/secret-injection", strings.NewReader(body))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent || rec.Header().Get("Cache-Control") != "no-store" || rec.Body.Len() != 0 {
		t.Fatalf("got %d, Cache-Control=%q, body=%q", rec.Code, rec.Header().Get("Cache-Control"), rec.Body.String())
	}
	wantBinding := application.MFAActionBinding{ActorUserID: "alice", SessionID: sess.ID, AccountID: "account-42", Protocol: "ssh", Action: "secret:inject"}
	if mfa.verifyBinding != wantBinding || mfa.proof.Challenge != "challenge-opaque" || mfa.proof.Factor != "totp" || mfa.proof.TOTPCode != "123456" {
		t.Fatalf("MFA verify received binding=%+v proof=%+v", mfa.verifyBinding, mfa.proof)
	}
	if mfa.consumed != "grant-must-not-leave-broker" {
		t.Fatalf("grant was not consumed inside Broker: %q", mfa.consumed)
	}
	if proxy.injectedSession != sess.ID || proxy.injectedAccount != "account-42" || proxy.injectedScope != "scope" {
		t.Fatalf("proxy injection = session %q account %q scope %q", proxy.injectedSession, proxy.injectedAccount, proxy.injectedScope)
	}
	if strings.Contains(rec.Body.String(), "grant-must-not-leave-broker") || strings.Contains(rec.Body.String(), "scope") {
		t.Fatalf("capability leaked to caller: %q", rec.Body.String())
	}
}

func TestSecretInjection_RejectsNonRequesterAndMalformedProofBeforeMFA(t *testing.T) {
	for name, body := range map[string]string{
		"non requester": `{"callerId":"mallory","actorRoles":["dba"],"challenge":"challenge","factor":"totp","totp_code":"123456"}`,
		"unknown field": `{"callerId":"alice","actorRoles":["dba"],"challenge":"challenge","factor":"totp","totp_code":"123456","accountId":"attacker"}`,
	} {
		t.Run(name, func(t *testing.T) {
			mfa, proxy := &stepUpMFA{}, &secretInjectionProxy{}
			_, handler, sess := newSecretInjectionServer(t, mfa, proxy)
			req := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/secret-injection", strings.NewReader(body))
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)
			if rec.Header().Get("Cache-Control") != "no-store" {
				t.Fatalf("Cache-Control = %q, want no-store", rec.Header().Get("Cache-Control"))
			}
			if name == "non requester" && rec.Code != http.StatusForbidden {
				t.Fatalf("non requester: %d %q", rec.Code, rec.Body.String())
			}
			if name == "unknown field" && rec.Code != http.StatusBadRequest {
				t.Fatalf("unknown field: %d %q", rec.Code, rec.Body.String())
			}
			if mfa.verifyBinding.ActorUserID != "" || proxy.injectedScope != "" {
				t.Fatal("invalid request reached MFA or proxy")
			}
		})
	}
}

func TestSecretInjection_MFAFailureDoesNotReachProxy(t *testing.T) {
	mfa, proxy := &stepUpMFA{verifyErr: errors.New("invalid factor")}, &secretInjectionProxy{}
	_, handler, sess := newSecretInjectionServer(t, mfa, proxy)
	req := httptest.NewRequest(http.MethodPost, "/sessions/"+sess.ID+"/secret-injection", strings.NewReader(`{"callerId":"alice","actorRoles":["dba"],"challenge":"challenge","factor":"totp","totp_code":"000000"}`))
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden || rec.Header().Get("Cache-Control") != "no-store" || proxy.injectedScope != "" {
		t.Fatalf("MFA failure: %d %q, proxy scope %q", rec.Code, rec.Body.String(), proxy.injectedScope)
	}
}

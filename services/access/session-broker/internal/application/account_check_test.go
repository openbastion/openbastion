package application_test

// ADR-0043: a session is created only on an account that exists and whose target's host key is
// pinned; a refusal is audited; a Vault that cannot be asked is a failure, not a refusal.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

func TestCreateSession_TheAccountMustExistAndBePinned(t *testing.T) {
	for name, c := range map[string]struct {
		checkErr  error
		want      error
		audited   bool
		available bool
	}{
		"unknown account":   {domain.ErrAccountNotFound, domain.ErrAccountNotFound, true, true},
		"not pinned":        {domain.ErrAccountNotPinned, domain.ErrAccountNotPinned, true, true},
		"the Vault is down": {errors.New("dial tcp 10.9.8.4:8081: connection refused"), domain.ErrUnavailable, false, false},
	} {
		t.Run(name, func(t *testing.T) {
			audit := &fakeAudit{}
			broker := newTestBroker(&fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, audit, &fakeAccountLookup{checkErr: c.checkErr}, &fakeProxyClient{})
			sess, err := broker.CreateSession(context.Background(), "alice", []string{"dba"}, "acc1", "ssh", "incident", 60)
			if sess != nil || !errors.Is(err, c.want) {
				t.Fatalf("got %v, %v; want %v", sess, err, c.want)
			}
			if got := strings.Join(audit.events, ","); (got == "session.create") != c.audited {
				t.Fatalf("audit %q", got)
			}
			if !c.available && errors.Is(err, domain.ErrAccountNotFound) {
				t.Fatal("a Vault failure was taken for a refusal")
			}
		})
	}
	// Counter-proof: a pinned account gets its session.
	broker := newTestBroker(&fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{}, &fakeProxyClient{})
	if sess, err := broker.CreateSession(context.Background(), "alice", []string{"dba"}, "acc1", "ssh", "incident", 60); err != nil || sess.Status != domain.StatusActive {
		t.Fatalf("a pinned account: %v %v", sess, err)
	}
}

// The account is not looked at before the access decision: a refused caller learns nothing of
// whether it exists.
func TestCreateSession_ARefusedCallerLearnsNothingOfTheAccount(t *testing.T) {
	accounts := &fakeAccountLookup{checkErr: domain.ErrAccountNotFound}
	broker := newTestBroker(&fakeAuthz{allowed: false, reason: "no policy"}, &fakeVaultAuthorizer{}, &fakeAudit{}, accounts, &fakeProxyClient{})
	_, err := broker.CreateSession(context.Background(), "mallory", []string{"x"}, "acc1", "ssh", "incident", 60)
	if err == nil || errors.Is(err, domain.ErrAccountNotFound) || !strings.Contains(err.Error(), "access denied") {
		t.Fatalf("got %v", err)
	}
}

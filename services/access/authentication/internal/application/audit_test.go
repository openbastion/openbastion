package application_test

// ADR-0064: no token that is not written to the audit first; the second factor's gestures written
// before they are made; refusals at best, in a budget; never a password, a code or a secret.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/pkg/refusalbudget"
	"github.com/openbastion/openbastion/services/access/authentication/internal/application"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type auditEvent struct {
	actor, action, resourceType, resourceID string
	success                                 bool
}

type fakeAudit struct {
	mu     sync.Mutex
	events []auditEvent
	down   bool
}

func (a *fakeAudit) EmitEvent(_ context.Context, actor, action, rt, rid string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.down {
		return errors.New("audit-service: connection refused")
	}
	a.events = append(a.events, auditEvent{actor, action, rt, rid, success})
	return nil
}

func (a *fakeAudit) actions() string {
	a.mu.Lock()
	defer a.mu.Unlock()
	var out []string
	for _, e := range a.events {
		out = append(out, e.action+":"+e.resourceID)
	}
	return strings.Join(out, " ")
}

func audited(t *testing.T) (*mfaWorld, *fakeAudit) {
	t.Helper()
	w := mfaService(t)
	a := &fakeAudit{}
	w.svc.WithAudit(a, refusalbudget.New(3, 1))
	return w, a
}

func TestAudit_ATokenIsIssuedOnlyOnceItsLoginIsWritten_TheAuditDownNobodyLogsIn(t *testing.T) {
	w, a := audited(t)
	ctx := context.Background()
	token, _, err := w.svc.Login(ctx, "dba", "dba-pass")
	if err != nil || token == "" {
		t.Fatal(err)
	}
	dba, _ := w.store.GetByUsername(ctx, "dba")
	if len(a.events) != 1 || a.events[0] != (auditEvent{dba.ID, application.ActionLogin, "account", "dba", true}) {
		t.Fatalf("events %+v", a.events)
	}
	a.down = true
	token, _, err = w.svc.Login(ctx, "dba", "dba-pass")
	if token != "" || !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("the audit down: token %q, %v — want no token and ErrAuditUnavailable", token, err)
	}
	// A wrong password stays a refusal, whatever the audit.
	if _, _, err := w.svc.Login(ctx, "dba", "wrong"); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatalf("a wrong password, the audit down: %v", err)
	}
}

func TestAudit_TheSecondFactorsLoginAndGesturesAreWrittenFirst_AndNotDoneWithoutTheAudit(t *testing.T) {
	w, a := audited(t)
	ctx := context.Background()
	secret := w.enroll(t)
	root, _ := w.store.GetByUsername(ctx, "root")
	got := a.actions()
	for _, want := range []string{"auth.mfa_enrollment_code_issued:local:root", "auth.mfa_enrolled:root", "auth.login_mfa:root"} {
		if !strings.Contains(got, want) {
			t.Fatalf("events %q lack %s", got, want)
		}
	}
	for _, e := range a.events {
		if e.action == application.ActionMFACodeIssued && e.actor != "admin-cli" {
			t.Fatalf("the code's actor is %q, want the caller", e.actor)
		}
	}
	if strings.Contains(got, "auth.login:root") {
		t.Fatal("a second-factor login written as auth.login")
	}

	// The audit down: no code is made, no reset is done, no token after a right code.
	a.down = true
	if code, _, err := w.svc.IssueEnrollmentCode(ctx, "admin-cli", domain.SourceLocal, "dba"); code != "" || !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("a code with the audit down: %q %v", code, err)
	}
	if err := w.svc.ResetMFA(ctx, "admin-cli", "root"); !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("a reset with the audit down: %v", err)
	}
	if sealed, _, _ := w.store.TOTP(ctx, root.ID); sealed == nil {
		t.Fatal("the reset was done without the audit")
	}
	a.down = false
	ch := w.challenge(t, "root", "root-pass", domain.MFAVerify)
	a.down = true
	*w.now = w.now.Add(60 * time.Second)
	// The code is right, and the audit cannot write the login: no token.
	token, _, err := w.svc.VerifyMFA(ctx, ch, code(t, secret, *w.now))
	if token != "" || !errors.Is(err, application.ErrAuditUnavailable) {
		t.Fatalf("a right code, the audit down: token %q, %v", token, err)
	}
}

func TestAudit_RefusalsAreWrittenAtBest_InABudgetPerLoginName_WithoutWhatWasTyped(t *testing.T) {
	w, a := audited(t)
	ctx := context.Background()
	for i := 0; i < 5; i++ {
		_, _, _ = w.svc.Login(ctx, "dba", fmt.Sprintf("guess-%d", i))
	}
	_, _, _ = w.svc.Login(ctx, "nobody", "pw")
	_, _, _ = w.svc.Login(ctx, "evil\nname\x00"+strings.Repeat("x", 400), "pw")
	var dba, nobody, evil int
	for _, e := range a.events {
		if e.action != application.ActionLoginRefused || e.success || e.resourceType != "login" || e.actor != "" {
			t.Fatalf("a refusal written as %+v", e)
		}
		if strings.Contains(e.resourceID, "guess-") || strings.Contains(e.resourceID, "pw") && e.resourceID != "nobody" {
			t.Fatalf("a password in the audit: %+v", e)
		}
		switch {
		case e.resourceID == "dba":
			dba++
		case e.resourceID == "nobody":
			nobody++
		case strings.HasPrefix(e.resourceID, "evil?name?"):
			evil++
			if len([]rune(e.resourceID)) > 260 || strings.ContainsAny(e.resourceID, "\n\x00") {
				t.Fatalf("an attacker's name kept as typed: %q", e.resourceID)
			}
		}
	}
	if dba != 3 || nobody != 1 || evil != 1 {
		t.Fatalf("refusals written: dba %d (budget 3 of 5), nobody %d, evil %d", dba, nobody, evil)
	}
	// The audit down, a refusal is still a refusal.
	a.down = true
	if _, _, err := w.svc.Login(ctx, "other", "pw"); !errors.Is(err, application.ErrInvalidCredentials) {
		t.Fatalf("%v", err)
	}
}

func TestAudit_ADirectoryLoginAndItsRefusalsAreWritten(t *testing.T) {
	w, a := audited(t)
	ctx := context.Background()
	w.svc.WithMFA(nil, w.store, nil) // no role requires the second factor here
	token, _, err := w.svc.LoginLDAP(ctx, "alice", "dir-pass")
	if err != nil || token == "" {
		t.Fatal(err)
	}
	_, _, _ = w.svc.LoginLDAP(ctx, "alice", "wrong")
	_, _, _ = w.svc.LoginLDAP(ctx, "alice", "")
	if got := a.actions(); got != "auth.login:ldap:"+w.dir.id.ID+" auth.login_refused:alice auth.login_refused:alice" {
		t.Fatalf("events %q", got)
	}
}

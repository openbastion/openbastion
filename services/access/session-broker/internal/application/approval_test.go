package application_test

// The approval of an ordinary session on an account that requires it (ADR-0067): the
// request carries a ticket in the declared format, waits, is decided by another person
// who holds session-approve:account:{id}, and every step is on the audit trail before it
// takes effect.

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

const (
	sessionApproveRes = application.SessionApproveResourcePrefix + acct
	goodTicket        = "CHG0001234"
)

// newGatedFixture is newApprovalFixture on an account that requires approval.
func newGatedFixture(t *testing.T, allow ...string) (*approvalFixture, *recordingNotifier) {
	t.Helper()
	f := newApprovalFixture(30, allow...)
	notifier := &recordingNotifier{}
	f.broker = application.NewSessionBrokerService(f.store, f.authz, f.vault, f.audit, &fakeAccountLookup{approvalRequired: true}, f.proxy).
		WithBreakGlass(30).WithClock(f.clock.Now).WithApprovalNotifier(notifier)
	return f, notifier
}

func (f *approvalFixture) ask(ticket string) (*domain.Session, error) {
	return f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "patch the database", ticket, 45)
}

func (f *approvalFixture) asked(t *testing.T) *domain.Session {
	t.Helper()
	sess, err := f.ask(goodTicket)
	if err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	return sess
}

func TestApprovalRequired_ARequestWaits_WithItsTicket(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess := f.asked(t)

	if sess.Status != domain.StatusPendingApproval || sess.BreakGlass || !sess.ApprovalRequired || sess.Ticket != goodTicket {
		t.Fatalf("a session on an account that requires approval must wait, with its ticket: %+v", sess)
	}
	if want := f.clock.Now().Add(application.DefaultBreakGlassApprovalWindow); !sess.ExpiresAt.Equal(want) {
		t.Fatalf("deadline = %v, want the decision window %v", sess.ExpiresAt, want)
	}
	if !f.audit.has("session.approval_requested", true) || f.audit.count("session.create") != 0 {
		t.Fatalf("the request is audited, and nothing is granted: %v", f.audit.events)
	}
	if !f.audit.hasTicket("session.approval_requested", true, goodTicket) {
		t.Fatalf("the request audit does not contain its ticket: %+v", f.audit.events)
	}
	if got := f.stored(t, sess.ID); got.Status != domain.StatusPendingApproval || got.Ticket != goodTicket || !got.ApprovalRequired {
		t.Fatalf("stored = %+v", got)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
		t.Fatal("a request waiting for approval was connectable")
	}
	f.untouched(t)

	if notifier.count() != 1 || notifier.got[0].Event != domain.NotifyApprovalRequested || notifier.got[0].Ticket != goodTicket {
		t.Fatalf("the approvers are told, with the ticket: %+v", notifier.got)
	}
}

func TestApprovalRequired_TheTicketFollowsTheFormat(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	for _, bad := range []string{"", "INC 1", "INC1;rm", "INC1\nforged line", strings.Repeat("a", 65), "é"} {
		before := len(f.audit.events)
		if _, err := f.ask(bad); !errors.Is(err, domain.ErrInvalidTicket) {
			t.Fatalf("ticket %q: err=%v, want ErrInvalidTicket", bad, err)
		}
		if got := f.audit.events[before:]; len(got) != 1 || got[0].action != "session.approval_requested" || got[0].success {
			t.Fatalf("ticket %q: the refusal must be audited as a refused request: %v", bad, got)
		}
		denied := f.stored(t, f.audit.events[before].resource)
		if denied.Status != domain.StatusDenied || denied.Ticket != "" {
			t.Fatalf("ticket %q: a refused request is recorded denied, without the ticket nobody accepted: %+v", bad, denied)
		}
	}
	if notifier.count() != 0 {
		t.Fatalf("a refused request is told to nobody: %+v", notifier.got)
	}
	for _, good := range []string{"INC0042", "CHG-2026/11:01_a.b", strings.Repeat("a", 64)} {
		if _, err := f.ask(good); err != nil {
			t.Fatalf("ticket %q in the default format: %v", good, err)
		}
		f.clock.advance(time.Hour) // the previous request expires: the pending limit is not under test here
	}
}

func TestApprovalRequired_ADeclaredPatternIsAnchored(t *testing.T) {
	re, err := application.CompileTicketPattern(`(INC|CHG)[0-9]{7}`)
	if err != nil {
		t.Fatal(err)
	}
	f, _ := newGatedFixture(t, sessionRes)
	f.broker.WithApprovalTicketPattern(re)
	for _, bad := range []string{"INC123", "INC00000011", "xINC0000001", "INC0000001 and more", "PRB0000001"} {
		if _, err := f.ask(bad); !errors.Is(err, domain.ErrInvalidTicket) {
			t.Fatalf("ticket %q against (INC|CHG)[0-9]{7}: err=%v", bad, err)
		}
	}
	if _, err := f.ask("CHG0000001"); err != nil {
		t.Fatalf("a ticket in the declared format: %v", err)
	}

	multiline, err := application.CompileTicketPattern(`(?m)INC`)
	if err != nil {
		t.Fatal(err)
	}
	f.broker.WithApprovalTicketPattern(multiline)
	f.clock.advance(time.Hour)
	if _, err := f.ask("INC\nforged-suffix"); !errors.Is(err, domain.ErrInvalidTicket) {
		t.Fatalf("a multiline pattern accepted a ticket with a suffix: %v", err)
	}

	// Even a pattern that accepts anything keeps the hard bound.
	any, _ := application.CompileTicketPattern(`.*`)
	f.broker.WithApprovalTicketPattern(any)
	f.clock.advance(time.Hour)
	if _, err := f.ask(strings.Repeat("x", application.MaxTicketBytes+1)); !errors.Is(err, domain.ErrInvalidTicket) {
		t.Fatalf("a ticket longer than %d bytes: %v", application.MaxTicketBytes, err)
	}
	if _, err := application.CompileTicketPattern(`(`); err == nil {
		t.Fatal("a pattern that does not compile must be refused")
	}
}

func TestApprovalRequired_TheSessionPolicyComesFirst(t *testing.T) {
	f, _ := newGatedFixture(t, sessionApproveRes) // no session:create on the account
	if _, err := f.ask(goodTicket); err == nil || errors.Is(err, domain.ErrInvalidTicket) {
		t.Fatalf("no policy: err=%v, want an access refusal", err)
	}
	if !f.audit.has("session.create", false) || f.audit.count("session.approval_requested") != 0 {
		t.Fatalf("refused as any session without a policy: %v", f.audit.events)
	}
}

func TestApprovalRequired_NoAuditNoRequest(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	f.audit.failOn = "session.approval_requested"
	if _, err := f.ask(goodTicket); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("err=%v, want ErrUnavailable", err)
	}
	pending, _, _ := f.store.ListPending(context.Background(), f.clock.Now(), 10)
	if len(pending) != 0 || notifier.count() != 0 {
		t.Fatalf("a request nobody could record waits anyway: %v, notified %d", ids(pending), notifier.count())
	}
}

func TestApprovalRequired_TheLimitOfRequestsWaitingIsShared(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, breakGlassRes, sessionApproveRes)
	f.broker.WithMaxPendingPerRequester(2)
	f.asked(t)
	f.request(t) // a break-glass request counts too
	if _, err := f.ask(goodTicket); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("a third request waiting: err=%v, want ErrTooManyPending", err)
	}
	if f.audit.count("session.approval_requested") != 2 || !f.audit.has("session.approval_requested", false) {
		t.Fatalf("the refusal is audited: %v", f.audit.events)
	}
}

func TestApprovalRequired_AnotherPersonApproves_AndTheSessionStartsThen(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess := f.asked(t)
	f.clock.advance(5 * time.Minute)

	approved, err := f.approve(sess.ID, approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if approved.Status != domain.StatusActive || approved.DecidedBy != approver {
		t.Fatalf("approved = %+v", approved)
	}
	if want := f.clock.Now().Add(45 * time.Minute); !approved.ExpiresAt.Equal(want) {
		t.Fatalf("the session lasts what was asked from the approval: ends %v, want %v", approved.ExpiresAt, want)
	}
	if !f.audit.has("session.approval_approved", true) || f.audit.count("session.breakglass_approved") != 0 {
		t.Fatalf("audit = %v", f.audit.events)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err != nil {
		t.Fatalf("Connect after approval: %v", err)
	}
	if f.proxy.lastBreakGlass {
		t.Fatal("an approved ordinary session carries no recording waiver")
	}
	if last := notifier.got[len(notifier.got)-1]; last.Event != domain.NotifyApprovalApproved || last.DecidedBy != approver || last.Ticket != goodTicket {
		t.Fatalf("notification = %+v", last)
	}

	// Decided once: the second decision loses.
	if _, err := f.reject(sess.ID, "another-lead"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a second decision: %v", err)
	}
}

func TestApprovalRequired_NobodyApprovesTheirOwnRequest(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, sessionApproveRes) // the requester holds the approval policy too
	sess := f.asked(t)
	if _, err := f.approve(sess.ID, requester); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-approval: %v", err)
	}
	if !f.audit.has("session.approval_approved", false) {
		t.Fatalf("the attempt is audited under the caller's name: %v", f.audit.events)
	}
	if !f.audit.hasTicket("session.approval_approved", false, goodTicket) {
		t.Fatalf("the refused decision does not retain the ticket in its audit event: %+v", f.audit.events)
	}
	if _, err := f.reject(sess.ID, requester); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-rejection: %v", err)
	}
	if !f.audit.hasTicket("session.approval_rejected", false, goodTicket) {
		t.Fatalf("the self-rejection does not retain the ticket in its audit event: %+v", f.audit.events)
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("a refused approval changed the request")
	}
}

func TestApprovalRequired_TheApproverNeedsTheAccountsApprovalPolicy(t *testing.T) {
	// The break-glass approvers' policy is not this one, nor is the session policy.
	f, _ := newGatedFixture(t, sessionRes, approveRes)
	sess := f.asked(t)
	for _, decide := range []func(string, string) (*domain.Session, error){f.approve, f.reject} {
		if _, err := decide(sess.ID, approver); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("a break-glass approver decided an approval request: %v", err)
		}
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("a refused decision changed the request")
	}
	if f.audit.count("session.approval_approved") != 1 || f.audit.count("session.approval_rejected") != 1 {
		t.Fatalf("both refusals are audited: %v", f.audit.events)
	}

	// And the reverse: session-approve does not decide a break-glass request.
	g, _ := newGatedFixture(t, sessionRes, breakGlassRes, sessionApproveRes)
	bg := g.request(t)
	if _, err := g.approve(bg.ID, approver); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("an account approver decided a break-glass request: %v", err)
	}
}

func TestApprovalRequired_RejectedOrExpired_NeverStarts(t *testing.T) {
	f, notifier := newGatedFixture(t, sessionRes, sessionApproveRes)
	rejected := f.asked(t)
	if got, err := f.reject(rejected.ID, approver); err != nil || got.Status != domain.StatusDenied {
		t.Fatalf("reject: %v %+v", err, got)
	}
	if !f.audit.has("session.approval_rejected", true) {
		t.Fatalf("audit = %v", f.audit.events)
	}
	if !f.audit.hasTicket("session.approval_rejected", true, goodTicket) {
		t.Fatalf("the rejection audit does not retain the ticket: %+v", f.audit.events)
	}
	if last := notifier.got[len(notifier.got)-1]; last.Event != domain.NotifyApprovalRejected {
		t.Fatalf("notification = %+v", last)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), rejected.ID, requester); err == nil {
		t.Fatal("a rejected request was connectable")
	}

	late := f.asked(t)
	f.clock.advance(application.DefaultBreakGlassApprovalWindow + time.Second)
	if _, err := f.approve(late.ID, approver); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("an expired request was approved: %v", err)
	}
	f.untouched(t)
}

func TestApprovalRequired_NoAuditNoDecision(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, sessionApproveRes)
	sess := f.asked(t)
	f.audit.failOn = "session.approval_approved"
	if _, err := f.approve(sess.ID, approver); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("err=%v, want ErrUnavailable", err)
	}
	if got := f.stored(t, sess.ID); got.Status != domain.StatusPendingApproval || got.DecidedBy != "" {
		t.Fatalf("a grant nobody could record was made: %+v", got)
	}
}

func TestApprovalRequired_ListedToWhoeverMayDecide_EvenWithBreakGlassOff(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, sessionApproveRes)
	f.broker.WithBreakGlass(0) // break-glass switched off: approval requests still wait
	sess := f.asked(t)

	items, total, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20)
	if err != nil || total != 1 || items[0].ID != sess.ID || items[0].Ticket != goodTicket {
		t.Fatalf("the approver sees the request and its ticket: %v %d %v", ids(items), total, err)
	}
	if mine, _, _, _ := f.broker.ListPendingApprovals(context.Background(), requester, []string{"sre"}, 1, 20); len(mine) != 0 {
		t.Fatalf("the requester is not shown their own request to decide: %v", ids(mine))
	}

	f.authz.allow[sessionApproveRes] = false
	f.authz.allow[approveRes] = true // a break-glass approver
	if items, _, _, _ := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); len(items) != 0 {
		t.Fatalf("shown to somebody who cannot decide it: %v", ids(items))
	}
}

func TestApprovalRequired_AnAccountThatRequiresNone_IsUnchanged(t *testing.T) {
	f := newApprovalFixture(30, sessionRes, sessionApproveRes)
	sess, err := f.ask(goodTicket)
	if err != nil || sess.Status != domain.StatusActive || sess.ApprovalRequired || sess.Ticket != "" {
		t.Fatalf("granted at once, the ticket ignored: %v %+v", err, sess)
	}
	// Asked of the break-glass approvers, whom this approver is not: forbidden, and
	// nothing changes.
	if _, err := f.approve(sess.ID, approver); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a session that waits for nothing cannot be decided: %v", err)
	}
	if f.stored(t, sess.ID).DecidedBy != "" {
		t.Fatal("a session that waited for nothing was decided")
	}
}

func TestApprovalRequired_ABreakGlassWaitsEvenWhenThePlatformLetsBreakGlassThrough(t *testing.T) {
	f, _ := newGatedFixture(t, sessionRes, breakGlassRes, approveRes)
	f.broker.WithoutBreakGlassApproval()
	sess := f.request(t)
	if sess.Status != domain.StatusPendingApproval || !sess.BreakGlass {
		t.Fatalf("an emergency waives the recording, not the second person the account asks for: %+v", sess)
	}
	if got, err := f.approve(sess.ID, approver); err != nil || got.Status != domain.StatusActive {
		t.Fatalf("decided by the break-glass approvers: %v %+v", err, got)
	}
}

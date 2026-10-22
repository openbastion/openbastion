package application_test

// The double validation of break-glass (ADR-0011) at the Session Broker: a request
// waits, a second person decides, nobody decides for themselves, and the decision is
// audited before it takes effect and taken only once.
//
// Everything here runs on the strict default — approval required — except where a
// test says otherwise, so that the default itself is what is proved.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const (
	approveRes = application.BreakGlassApproveResourcePrefix + acct
	requester  = "oncall"
	approver   = "lead"
)

// everything is what a deployment would grant for this account: the ordinary session,
// the request and the approval — three distinct resources, three distinct policies.
var everything = []string{sessionRes, breakGlassRes, approveRes}

type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

type approvalFixture struct {
	broker *application.SessionBrokerService
	authz  *resourceAuthz
	audit  *journalAudit
	vault  *fakeVaultAuthorizer
	proxy  *fakeProxyClient
	store  *infrastructure.InMemoryStore
	clock  *fakeClock
}

// newApprovalFixture builds a Broker that has never been told anything about approval:
// the strict default is the one under test.
func newApprovalFixture(maxMinutes int, allow ...string) *approvalFixture {
	f := &approvalFixture{
		authz: &resourceAuthz{allow: map[string]bool{}}, audit: &journalAudit{}, vault: &fakeVaultAuthorizer{},
		proxy: &fakeProxyClient{}, store: infrastructure.NewInMemoryStore(),
		clock: &fakeClock{t: time.Date(2026, 10, 21, 3, 0, 0, 0, time.UTC)},
	}
	for _, r := range allow {
		f.authz.allow[r] = true
	}
	f.broker = application.NewSessionBrokerService(f.store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(maxMinutes).WithClock(f.clock.Now)
	return f
}

func (f *approvalFixture) request(t *testing.T) *domain.Session {
	t.Helper()
	sess, err := f.broker.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20)
	if err != nil {
		t.Fatalf("CreateBreakGlassSession: %v", err)
	}
	return sess
}

func (f *approvalFixture) approve(id, by string) (*domain.Session, error) {
	return f.broker.ApproveBreakGlass(context.Background(), id, by, []string{"lead"})
}

func (f *approvalFixture) reject(id, by string) (*domain.Session, error) {
	return f.broker.RejectBreakGlass(context.Background(), id, by, []string{"lead"})
}

func (f *approvalFixture) stored(t *testing.T, id string) *domain.Session {
	t.Helper()
	sess, err := f.store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("store.Get: %v", err)
	}
	return sess
}

// untouched says that nothing reached the Vault or the proxy: a request that is not
// granted must not have cost a scope, still less a ticket.
func (f *approvalFixture) untouched(t *testing.T) {
	t.Helper()
	if f.vault.calls != 0 || f.proxy.calls != 0 {
		t.Fatalf("the Vault was asked %d time(s) and the proxy %d: nothing should have been", f.vault.calls, f.proxy.calls)
	}
}

// -- the request waits ---------------------------------------------------------------

func TestApproval_IsRequiredByDefault_AndARequestWaitsForIt(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)

	if sess.Status != domain.StatusPendingApproval || !sess.BreakGlass {
		t.Fatalf("a request that passed ADR-0009's locks must wait, got %+v", sess)
	}
	if !f.audit.has("session.breakglass_requested", true) {
		t.Fatalf("the request itself must be audited: %v", f.audit.events)
	}
	if f.audit.count("session.create") != 0 {
		t.Fatalf("nothing was granted, so no session.create: %v", f.audit.events)
	}
	if got := f.stored(t, sess.ID); got.Status != domain.StatusPendingApproval || got.DurationMinutes != 20 {
		t.Fatalf("stored = %+v", got)
	}

	// Waiting is not a session: not for the requester, who is the one it is for.
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
		t.Fatal("a request waiting for approval was connectable")
	}
	f.untouched(t)
}

func TestApproval_AnOrdinarySessionIsNotAffected(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "routine", 20)
	if err != nil || sess.Status != domain.StatusActive {
		t.Fatalf("approval is for break-glass only: %v %+v", err, sess)
	}
	if _, err := f.approve(sess.ID, approver); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("approving an ordinary session: %v, want a conflict", err)
	}
}

// -- the second person ---------------------------------------------------------------

func TestApproval_ASecondPersonApproves_AndTheClockStartsThen(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	requestedAt := f.clock.Now()
	if want := requestedAt.Add(application.DefaultBreakGlassApprovalWindow); !sess.ExpiresAt.Equal(want) {
		t.Fatalf("while waiting, ExpiresAt is the decision deadline: %v, want %v", sess.ExpiresAt, want)
	}

	f.clock.advance(10 * time.Minute) // the on-call takes ten minutes to be reached
	approvedAt := f.clock.Now()
	got, err := f.approve(sess.ID, approver)
	if err != nil {
		t.Fatalf("approve: %v", err)
	}
	if got.Status != domain.StatusActive || got.DecidedBy != approver || got.DecidedAt == nil || !got.DecidedAt.Equal(approvedAt) {
		t.Fatalf("approved = %+v", got)
	}
	// The ten minutes of waiting are not taken out of the twenty that were asked for.
	if want := approvedAt.Add(20 * time.Minute); !got.ExpiresAt.Equal(want) {
		t.Fatalf("the session ends at %v, want approval + 20 minutes = %v", got.ExpiresAt, want)
	}
	if stored := f.stored(t, sess.ID); stored.Status != domain.StatusActive || stored.DecidedBy != approver || !stored.ExpiresAt.Equal(got.ExpiresAt) {
		t.Fatalf("the decision was not stored: %+v", stored)
	}

	// Who decided, on what authority: the approval resource, not the request's.
	if !f.audit.has("session.breakglass_approved", true) {
		t.Fatalf("the approval must be audited: %v", f.audit.events)
	}
	last := f.audit.events[len(f.audit.events)-1]
	if last.actor != approver || last.resource != sess.ID {
		t.Fatalf("the approval is attributed to %q on %q, want %q on the session", last.actor, last.resource, approver)
	}
	if f.authz.asked[len(f.authz.asked)-1] != approveRes {
		t.Fatalf("the approval was judged on %v, want the approval resource %q", f.authz.asked, approveRes)
	}

	// The requester — and only the requester — can now connect, with the waiver.
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err != nil {
		t.Fatalf("Connect after approval: %v", err)
	}
	if !f.proxy.lastBreakGlass {
		t.Fatal("an approved break-glass session must carry the waiver to the proxy")
	}
}

func TestApproval_NobodyApprovesTheirOwnRequest(t *testing.T) {
	// The requester holds the approval policy as well — the worst case. It is the
	// identity that is compared, not the role.
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)

	_, err := f.approve(sess.ID, requester)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("self-approval: %v, want forbidden", err)
	}
	if !f.audit.has("session.breakglass_approved", false) || f.audit.has("session.breakglass_approved", true) {
		t.Fatalf("a refused self-approval is audited as a failure, and never as a success: %v", f.audit.events)
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("a refused approval changed the request")
	}
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
		t.Fatal("the requester connected after approving their own request")
	}
	f.untouched(t)
}

func TestApproval_NeedsItsOwnPolicy(t *testing.T) {
	for name, allow := range map[string][]string{
		"no policy at all":                 {sessionRes, breakGlassRes},
		"the request policy only":          {breakGlassRes},
		"the ordinary session policy only": {sessionRes},
	} {
		t.Run(name, func(t *testing.T) {
			f := newApprovalFixture(30, everything...)
			sess := f.request(t)
			// From here, only `allow` is granted.
			f.authz.mu.Lock()
			f.authz.allow = map[string]bool{}
			for _, r := range allow {
				f.authz.allow[r] = true
			}
			f.authz.mu.Unlock()

			if _, err := f.approve(sess.ID, approver); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("%s: %v, want forbidden", name, err)
			}
			if !f.audit.has("session.breakglass_approved", false) {
				t.Fatalf("the refusal must be audited: %v", f.audit.events)
			}
			if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
				t.Fatal("an unauthorised approval changed the request")
			}
		})
	}
}

func TestApproval_RequiresTheAuthorizationServiceToAnswer(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	f.authz.failOn = approveRes

	_, err := f.approve(sess.ID, approver)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("%v, want unavailable (fail closed)", err)
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("a decision nobody could authorise was taken")
	}
}

func TestApproval_NoDecisionWithoutAnIdentity(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	if _, err := f.approve(sess.ID, ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("an anonymous approval: %v", err)
	}
	if _, err := f.broker.ApproveBreakGlass(context.Background(), "no-such-session", approver, nil); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown session: %v, want not found", err)
	}
}

// -- the decision is audited first, and taken once -----------------------------------

func TestApproval_FailsClosed_WhenTheDecisionCannotBeAudited(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	f.audit.failOn = "session.breakglass_approved"

	_, err := f.approve(sess.ID, approver)
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("%v, want unavailable", err)
	}
	if got := f.stored(t, sess.ID); got.Status != domain.StatusPendingApproval || got.DecidedBy != "" {
		t.Fatalf("a grant nobody could record was made: %+v", got)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
		t.Fatal("connected although the approval was never recorded")
	}

	// Refused for as long as it fails — not for good: the request is still waiting.
	f.audit.stopFailing()
	if _, err := f.approve(sess.ID, approver); err != nil {
		t.Fatalf("approve once the audit is back: %v", err)
	}
}

func TestApproval_ADecisionIsTakenOnce(t *testing.T) {
	type decision func(f *approvalFixture, id, by string) (*domain.Session, error)
	approveIt := decision(func(f *approvalFixture, id, by string) (*domain.Session, error) { return f.approve(id, by) })
	rejectIt := decision(func(f *approvalFixture, id, by string) (*domain.Session, error) { return f.reject(id, by) })
	for name, c := range map[string]struct{ first, second decision }{
		"approve then approve": {approveIt, approveIt},
		"approve then reject":  {approveIt, rejectIt},
		"reject then approve":  {rejectIt, approveIt},
		"reject then reject":   {rejectIt, rejectIt},
	} {
		t.Run(name, func(t *testing.T) {
			f := newApprovalFixture(30, everything...)
			sess := f.request(t)
			first, err := c.first(f, sess.ID, approver)
			if err != nil {
				t.Fatalf("first decision: %v", err)
			}
			if _, err := c.second(f, sess.ID, "another-lead"); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("second decision: %v, want a conflict", err)
			}
			if got := f.stored(t, sess.ID); got.Status != first.Status || got.DecidedBy != approver {
				t.Fatalf("the first decision did not stand: %+v", got)
			}
		})
	}
}

func TestApproval_AConcurrentDecisionHasExactlyOneWinner(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for round := 0; round < 60; round++ {
		sess := f.request(t)
		var wg sync.WaitGroup
		results := make(chan string, 3)
		for _, c := range []struct {
			name string
			do   func() error
		}{
			{"approve-1", func() error { _, err := f.approve(sess.ID, "lead-1"); return err }},
			{"approve-2", func() error { _, err := f.approve(sess.ID, "lead-2"); return err }},
			{"reject", func() error { _, err := f.reject(sess.ID, "lead-3"); return err }},
		} {
			c := c
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := c.do(); err == nil {
					results <- c.name
				} else if !errors.Is(err, domain.ErrConflict) {
					t.Errorf("%s: %v", c.name, err)
				}
			}()
		}
		wg.Wait()
		close(results)
		var winners []string
		for w := range results {
			winners = append(winners, w)
		}
		if len(winners) != 1 {
			t.Fatalf("round %d: %d decisions took effect (%v), want exactly one", round, len(winners), winners)
		}
		// The stored session is the winner's, whole: its status and its name.
		want := map[string]struct {
			status domain.SessionStatus
			by     string
		}{
			"approve-1": {domain.StatusActive, "lead-1"},
			"approve-2": {domain.StatusActive, "lead-2"},
			"reject":    {domain.StatusDenied, "lead-3"},
		}[winners[0]]
		if got := f.stored(t, sess.ID); got.Status != want.status || got.DecidedBy != want.by {
			t.Fatalf("round %d: %s won but the session is %+v", round, winners[0], got)
		}
	}
}

// -- reject ---------------------------------------------------------------------------

func TestApproval_ARejectedRequestNeverConnects(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)

	got, err := f.reject(sess.ID, approver)
	if err != nil {
		t.Fatalf("reject: %v", err)
	}
	if got.Status != domain.StatusDenied || got.DecidedBy != approver {
		t.Fatalf("rejected = %+v", got)
	}
	if !f.audit.has("session.breakglass_rejected", true) {
		t.Fatalf("the rejection must be audited: %v", f.audit.events)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
		t.Fatal("a rejected request connected")
	}
	f.untouched(t)
}

// A stranger must not be able to kill someone's emergency request: rejecting needs the
// same authority as approving.
func TestApproval_RejectNeedsTheApprovalAuthority(t *testing.T) {
	f := newApprovalFixture(30, sessionRes, breakGlassRes) // no approval policy for anybody
	sess := f.request(t)
	if _, err := f.reject(sess.ID, "stranger"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger rejected a request: %v", err)
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("the request was changed by someone with no authority over it")
	}
}

// To withdraw one's own request is not an escalation: the rule against deciding for
// oneself is for approval only.
func TestApproval_TheRequesterMayWithdrawTheirOwnRequest(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	got, err := f.reject(sess.ID, requester)
	if err != nil || got.Status != domain.StatusDenied {
		t.Fatalf("self-reject: %v %+v", err, got)
	}
}

// -- time -----------------------------------------------------------------------------

func TestApproval_ARequestExpiresUnlessDecidedInTime(t *testing.T) {
	for name, c := range map[string]struct {
		window  time.Duration // 0 = the default
		wait    time.Duration
		allowed bool
	}{
		"inside the default window":         {0, 14*time.Minute + 59*time.Second, true},
		"after the default window":          {0, 15*time.Minute + time.Second, false},
		"inside a short window":             {2 * time.Minute, time.Minute, true},
		"after a short window":              {2 * time.Minute, 3 * time.Minute, false},
		"after a long window, still inside": {time.Hour, 59 * time.Minute, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newApprovalFixture(30, everything...)
			if c.window > 0 {
				f.broker.WithBreakGlassApprovalWindow(c.window)
			}
			sess := f.request(t)
			f.clock.advance(c.wait)

			got, err := f.approve(sess.ID, approver)
			if c.allowed {
				if err != nil || got.Status != domain.StatusActive {
					t.Fatalf("approve: %v %+v", err, got)
				}
				return
			}
			if !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("approving an expired request: %v, want a conflict", err)
			}
			// Read back, the request says what happened to it, and the stored row is untouched.
			if seen, _ := f.broker.GetSession(context.Background(), sess.ID); seen.Status != domain.StatusExpired {
				t.Fatalf("GetSession says %q, want expired", seen.Status)
			}
			if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
				t.Fatal("expiry must be read, not written")
			}
			if _, err := f.reject(sess.ID, approver); !errors.Is(err, domain.ErrConflict) {
				t.Fatalf("rejecting an expired request: %v, want a conflict", err)
			}
			if _, _, _, err := f.broker.Connect(context.Background(), sess.ID, requester); err == nil {
				t.Fatal("an expired request connected")
			}
		})
	}
}

// -- the rules of the day of the approval, not of the day of the request --------------

func TestApproval_SwitchingBreakGlassOffReachesTheRequestsAlreadyWaiting(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	f.broker.WithBreakGlass(0) // the operator turns it off while the request waits

	_, err := f.approve(sess.ID, approver)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("approval while break-glass is off: %v, want forbidden", err)
	}
	// The reason is the true one: "off", not a limit that happens to be zero.
	if !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("the refusal does not say that break-glass is off: %v", err)
	}
	if f.stored(t, sess.ID).Status != domain.StatusPendingApproval {
		t.Fatal("the request was granted although the platform no longer grants break-glass")
	}
}

func TestApproval_ALowerLimitReachesTheRequestsAlreadyWaiting(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t) // 20 minutes
	f.broker.WithBreakGlass(10)

	if _, err := f.approve(sess.ID, approver); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("approval of 20 minutes under a 10 minute limit: %v, want forbidden", err)
	}
	// Rejecting is still possible: tightening the limit must not trap the request.
	if _, err := f.reject(sess.ID, approver); err != nil {
		t.Fatalf("reject: %v", err)
	}
}

// -- the weak mode, by name -----------------------------------------------------------

func TestApproval_CanBeTurnedOffOnlyByName(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.broker.WithoutBreakGlassApproval()
	sess := f.request(t)
	if sess.Status != domain.StatusActive || f.audit.count("session.create") != 1 {
		t.Fatalf("without approval the request is granted at once, as under ADR-0009: %+v %v", sess, f.audit.events)
	}
}

// -- only the requester connects ------------------------------------------------------

func TestConnect_OnlyTheRequesterMayConnect(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	ordinary, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "routine", 20)
	if err != nil {
		t.Fatal(err)
	}
	bg := f.request(t)
	if _, err := f.approve(bg.ID, approver); err != nil {
		t.Fatal(err)
	}

	for name, c := range map[string]struct{ id, caller string }{
		"another user, ordinary session": {ordinary.ID, "mallory"},
		"nobody, ordinary session":       {ordinary.ID, ""},
		"the approver, approved session": {bg.ID, approver},
		"another user, approved session": {bg.ID, "mallory"},
		"nobody, approved session":       {bg.ID, ""},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, _, err := f.broker.Connect(context.Background(), c.id, c.caller)
			if !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("%v, want forbidden", err)
			}
			f.untouched(t)
		})
	}

	// The control: the requester does get in, on both.
	for _, id := range []string{ordinary.ID, bg.ID} {
		if _, _, _, err := f.broker.Connect(context.Background(), id, requester); err != nil {
			t.Fatalf("the requester was refused: %v", err)
		}
	}
}

// Turning approval on takes effect on break-glass sessions granted before: without an
// approver on record they run under "record or refuse", exactly like switching
// break-glass off (ADR-0009).
func TestApproval_ASessionGrantedBeforeItWasRequiredGetsNoWaiver(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	build := func(proxy *fakeProxyClient) *application.SessionBrokerService {
		return application.NewSessionBrokerService(store, &resourceAuthz{allow: map[string]bool{sessionRes: true, breakGlassRes: true}},
			&fakeVaultAuthorizer{}, &journalAudit{}, &fakeAccountLookup{}, proxy).WithBreakGlass(30)
	}
	oldProxy, newProxy := &fakeProxyClient{}, &fakeProxyClient{}
	before := build(oldProxy).WithoutBreakGlassApproval() // the platform as it was
	after := build(newProxy)                              // the same platform, approval now required

	sess, err := before.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20)
	if err != nil || sess.Status != domain.StatusActive {
		t.Fatalf("under the earlier regime: %v %+v", err, sess)
	}
	if _, _, _, err := before.Connect(context.Background(), sess.ID, requester); err != nil || !oldProxy.lastBreakGlass {
		t.Fatalf("control: with approval off the waiver is passed on: %v %v", err, oldProxy.lastBreakGlass)
	}
	if _, _, _, err := after.Connect(context.Background(), sess.ID, requester); err != nil {
		t.Fatalf("it still connects: %v", err)
	}
	if newProxy.lastBreakGlass {
		t.Fatal("approval is now required and nobody approved this session: the waiver must not reach the proxy")
	}
}

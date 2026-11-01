package application_test

// Finding a break-glass request that waits, and being told of it (ADR-0012): the
// approver sees what he may decide and nothing else, the listing never lies by
// omission, and a notification is sent only of what happened — and carries nothing
// that a channel's readers should not read.

import (
	"context"
	"errors"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const (
	acct2          = "acc-prod-web"
	sessionRes2    = "vault:account:" + acct2
	breakGlassRes2 = application.BreakGlassResourcePrefix + acct2
	approveRes2    = application.BreakGlassApproveResourcePrefix + acct2
)

// two accounts, with the requester allowed to ask on both and the approver — for now —
// allowed to approve on the first only.
var twoAccounts = []string{sessionRes, breakGlassRes, approveRes, sessionRes2, breakGlassRes2}

func (f *approvalFixture) requestOn(t *testing.T, account, by string) *domain.Session {
	t.Helper()
	sess, err := f.broker.CreateBreakGlassSession(context.Background(), by, []string{"sre"}, account, "ssh", goodReason, 20)
	if err != nil {
		t.Fatalf("CreateBreakGlassSession(%s): %v", account, err)
	}
	return sess
}

// seedPending writes a pending request straight into the store, as another Broker
// replica (or a bug) might have left it.
func (f *approvalFixture) seedPending(t *testing.T, id, by, account string, minutes int, breakGlass bool) {
	t.Helper()
	now := f.clock.Now()
	err := f.store.Save(context.Background(), &domain.Session{
		ID: id, Status: domain.StatusPendingApproval, Protocol: "ssh", RequestedBy: by, PrivilegedAccountID: account,
		Justification: goodReason, CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute), DurationMinutes: minutes, BreakGlass: breakGlass,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func (f *approvalFixture) list(t *testing.T, caller string, page, size int) ([]*domain.Session, int, bool) {
	t.Helper()
	items, total, truncated, err := f.broker.ListPendingApprovals(context.Background(), caller, []string{"lead"}, page, size)
	if err != nil {
		t.Fatalf("ListPendingApprovals: %v", err)
	}
	if items == nil {
		t.Fatal("the list is nil: it must be an empty list, which a client reads as `[]`")
	}
	return items, total, truncated
}

func ids(items []*domain.Session) []string {
	out := make([]string, 0, len(items))
	for _, s := range items {
		out = append(out, s.ID)
	}
	return out
}

// -- the list: what the caller may decide ----------------------------------------------

func TestListPending_ShowsOnlyWhatTheCallerMayDecide(t *testing.T) {
	f := newApprovalFixture(30, twoAccounts...)
	a := f.request(t)
	f.clock.advance(time.Minute)
	b := f.requestOn(t, acct2, requester)

	items, total, truncated := f.list(t, approver, 1, 20)
	if got := ids(items); len(got) != 1 || got[0] != a.ID || total != 1 || truncated {
		t.Fatalf("with authority on one account the list is %v (total %d, truncated %v), want only %s", got, total, truncated, a.ID)
	}
	if items[0].Justification != goodReason {
		t.Fatal("the approver decides on the justification: the list must carry it")
	}

	// The authority is per account: grant the second, and the second shows — after the
	// first, whose deadline is sooner.
	f.authz.allow[approveRes2] = true
	items, total, _ = f.list(t, approver, 1, 20)
	if got := ids(items); len(got) != 2 || got[0] != a.ID || got[1] != b.ID || total != 2 {
		t.Fatalf("with authority on both, the list is %v (total %d), want [%s %s] soonest deadline first", got, total, a.ID, b.ID)
	}
}

func TestListPending_TheCallersRolesAreTheOnesThatAreAsked(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t)
	if _, _, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead", "sre"}, 1, 20); err != nil {
		t.Fatal(err)
	}
	f.authz.mu.Lock()
	defer f.authz.mu.Unlock()
	last := f.authz.asked[len(f.authz.asked)-1]
	if last != approveRes || !reflect.DeepEqual(f.authz.askedRoles[len(f.authz.askedRoles)-1], []string{"lead", "sre"}) {
		t.Fatalf("the Authorization Service was asked %q for roles %v: it must be the approval resource, for the caller's roles", last, f.authz.askedRoles)
	}
}

func TestListPending_NeverShowsTheCallersOwnRequests(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	mine := f.request(t) // by `requester`

	// Even holding the approval authority, the author does not find his own request in
	// what he may decide: he cannot approve it, and he knows it.
	if items, total, _ := f.list(t, requester, 1, 20); len(items) != 0 || total != 0 {
		t.Fatalf("the author sees his own request in the list of what he may decide: %v", ids(items))
	}
	if items, _, _ := f.list(t, approver, 1, 20); len(items) != 1 || items[0].ID != mine.ID {
		t.Fatalf("somebody else does not see it either: %v", ids(items))
	}
}

func TestListPending_NoAuthorityIsAnEmptyList_NotARefusal_AndItSaysNothing(t *testing.T) {
	// Requests exist, and the caller holds no approval policy.
	f := newApprovalFixture(30, sessionRes, breakGlassRes)
	f.request(t)
	items, total, truncated := f.list(t, "stranger", 1, 20)
	if len(items) != 0 || total != 0 || truncated {
		t.Fatalf("no authority: items=%v total=%d truncated=%v", ids(items), total, truncated)
	}

	// The answer is the same as when nothing is pending at all: it is not an oracle
	// for the existence of break-glass requests.
	empty := newApprovalFixture(30, sessionRes, breakGlassRes)
	items2, total2, truncated2 := empty.list(t, "stranger", 1, 20)
	if len(items2) != len(items) || total2 != total || truncated2 != truncated {
		t.Fatalf("the answer differs when requests exist (%v %d %v) and when none does (%v %d %v)", items, total, truncated, items2, total2, truncated2)
	}
}

func TestListPending_OnlyWhatIsStillPending(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	approved := f.request(t)
	rejected := f.request(t)
	expired := f.request(t)
	if _, err := f.approve(approved.ID, approver); err != nil {
		t.Fatal(err)
	}
	if _, err := f.reject(rejected.ID, approver); err != nil {
		t.Fatal(err)
	}
	// Past the deadline of the three, a fourth is asked for: the one that waits.
	f.clock.advance(application.DefaultBreakGlassApprovalWindow + time.Minute)
	waiting := f.request(t)

	items, total, _ := f.list(t, approver, 1, 20)
	if got := ids(items); len(got) != 1 || got[0] != waiting.ID || total != 1 {
		t.Fatalf("the list is %v, want only %s (not %s approved, %s rejected, %s expired)", got, waiting.ID, approved.ID, rejected.ID, expired.ID)
	}
}

func TestListPending_FollowsTodaysRules_NotTheDayOfTheRequest(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t) // 20 minutes
	f.seedPending(t, "session_zero", "someone", acct, 0, true)
	if items, _, _ := f.list(t, approver, 1, 20); len(items) != 1 {
		t.Fatalf("before the rules change: %v", ids(items))
	}

	// The limit comes down under what was asked: approving it would be refused, so it
	// is not offered. (A request that records no duration is never offered either.)
	lower := application.NewSessionBrokerService(f.store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(10).WithClock(f.clock.Now)
	if items, _, _, err := lower.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); err != nil || len(items) != 0 {
		t.Fatalf("limit lowered to 10: items=%v err=%v", ids(items), err)
	}

	// And with break-glass switched off, nothing can be approved, so nothing is listed
	// — and nobody is asked anything.
	off := application.NewSessionBrokerService(f.store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(0).WithClock(f.clock.Now)
	before := len(f.authz.asked)
	if items, _, _, err := off.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); err != nil || len(items) != 0 {
		t.Fatalf("switched off: items=%v err=%v", ids(items), err)
	}
	if len(f.authz.asked) != before {
		t.Fatal("the Authorization Service was asked about requests that cannot be approved anyway")
	}
}

func TestListPending_ARowThatIsNotABreakGlassRequestIsNeverListed(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.seedPending(t, "session_odd", "someone", acct, 20, false)
	if items, _, _ := f.list(t, approver, 1, 20); len(items) != 0 {
		t.Fatalf("a pending row that is not a break-glass request was listed: %v", ids(items))
	}
}

func TestListPending_TheAuthorizationServiceIsAskedOncePerAccount(t *testing.T) {
	f := newApprovalFixture(30, twoAccounts...)
	f.broker.WithMaxPendingPerRequester(100) // this test is not about the quota (ADR-0013)
	f.authz.allow[approveRes2] = true
	for i := 0; i < 3; i++ {
		f.request(t)
	}
	f.requestOn(t, acct2, requester)
	f.authz.mu.Lock()
	f.authz.asked = nil
	f.authz.mu.Unlock()

	items, _, _ := f.list(t, approver, 1, 20)
	if len(items) != 4 {
		t.Fatalf("expected the 4 requests, got %v", ids(items))
	}
	f.authz.mu.Lock()
	defer f.authz.mu.Unlock()
	asked := append([]string(nil), f.authz.asked...)
	sort.Strings(asked)
	if want := []string{approveRes, approveRes2}; !reflect.DeepEqual(asked, want) {
		t.Fatalf("the Authorization Service was asked %v, want one question per distinct account %v", asked, want)
	}
}

func TestListPending_FailsClosed_NeverAPartialList(t *testing.T) {
	f := newApprovalFixture(30, twoAccounts...)
	f.authz.allow[approveRes2] = true
	f.request(t)
	f.requestOn(t, acct2, requester)

	f.authz.failOn = approveRes2 // the first account answers, the second does not
	items, _, _, err := f.broker.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20)
	if !errors.Is(err, domain.ErrUnavailable) || items != nil {
		t.Fatalf("items=%v err=%v: a list that lacks a request without saying so is worse than none", ids(items), err)
	}

	f.authz.failOn = ""
	failing := &listFailingStore{InMemoryStore: f.store}
	broken := application.NewSessionBrokerService(failing, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithClock(f.clock.Now)
	if _, _, _, err := broken.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("a store that cannot list: err=%v, want ErrUnavailable", err)
	}

	// With break-glass switched off, requests on accounts that require approval still
	// wait (ADR-0067): the list asks the store, and a store that is down is still an
	// error, never an empty list.
	off := application.NewSessionBrokerService(failing, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(0).WithClock(f.clock.Now)
	if items, _, _, err := off.ListPendingApprovals(context.Background(), approver, []string{"lead"}, 1, 20); !errors.Is(err, domain.ErrUnavailable) || items != nil {
		t.Fatalf("switched off, store down: items=%v err=%v, want ErrUnavailable", items, err)
	}
}

type listFailingStore struct{ *infrastructure.InMemoryStore }

func (listFailingStore) ListPending(context.Context, time.Time, int) ([]*domain.Session, bool, error) {
	return nil, false, errors.New("database unreachable")
}

func TestListPending_NeedsAnAuthenticatedCaller(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.request(t)
	before := len(f.authz.asked)
	_, _, _, err := f.broker.ListPendingApprovals(context.Background(), "", []string{"lead"}, 1, 20)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("err=%v, want ErrForbidden", err)
	}
	if len(f.authz.asked) != before {
		t.Fatal("something was asked before the caller was known")
	}
}

func TestListPending_PaginatesTheFilteredList(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.broker.WithMaxPendingPerRequester(100) // five requests from one requester: not what this test is about (ADR-0013)
	var all []string
	for i := 0; i < 5; i++ {
		f.clock.advance(time.Second)
		all = append(all, f.request(t).ID)
	}

	items, total, _ := f.list(t, approver, 1, 2)
	if len(items) != 2 || total != 5 || items[0].ID != all[0] || items[1].ID != all[1] {
		t.Fatalf("page 1: %v total %d, want the 2 soonest of 5", ids(items), total)
	}
	items, total, _ = f.list(t, approver, 3, 2)
	if len(items) != 1 || total != 5 || items[0].ID != all[4] {
		t.Fatalf("page 3: %v total %d, want the 5th", ids(items), total)
	}
	items, total, _ = f.list(t, approver, 4, 2)
	if len(items) != 0 || total != 5 {
		t.Fatalf("page 4: %v total %d, want an empty page that still says 5", ids(items), total)
	}
}

func TestClampPage(t *testing.T) {
	for _, c := range []struct{ page, size, wantPage, wantSize int }{
		{0, 0, 1, 20}, {-3, 101, 1, 20}, {2, 100, 2, 100}, {3, 1, 3, 1}, {1, -1, 1, 20}, {7, 20, 7, 20},
	} {
		if p, s := application.ClampPage(c.page, c.size); p != c.wantPage || s != c.wantSize {
			t.Errorf("ClampPage(%d, %d) = (%d, %d), want (%d, %d)", c.page, c.size, p, s, c.wantPage, c.wantSize)
		}
	}
}

func TestListPending_SaysWhenItWasCut(t *testing.T) {
	for _, c := range []struct {
		pending   int
		truncated bool
	}{{application.MaxPendingScanned, false}, {application.MaxPendingScanned + 1, true}} {
		f := newApprovalFixture(30, everything...)
		for i := 0; i < c.pending; i++ {
			f.seedPending(t, "session_seed_"+string(rune('a'+i/26))+string(rune('a'+i%26)), "someone", acct, 20, true)
		}
		items, total, truncated := f.list(t, approver, 1, 100)
		if truncated != c.truncated || len(items) != application.MaxPendingScanned || total != application.MaxPendingScanned {
			t.Fatalf("%d pending: %d items, total %d, truncated %v; want %d items and truncated=%v",
				c.pending, len(items), total, truncated, application.MaxPendingScanned, c.truncated)
		}
		// The cut is said on every page, the empty one past the end included: whoever reads
		// page 2 must not conclude that nothing was left out.
		if items, _, truncated = f.list(t, approver, 2, 100); len(items) != 0 || truncated != c.truncated {
			t.Fatalf("%d pending, page 2: %d items, truncated %v; want none and truncated=%v", c.pending, len(items), truncated, c.truncated)
		}
	}
}

// -- the account identifier of a break-glass request -----------------------------------

func TestBreakGlass_AnAccountIdentifierThatIsNotAnIdentifierIsRefused(t *testing.T) {
	notifier := &recordingNotifier{}
	for _, bad := range []string{
		"", "two words", "<!channel>", "acc\nINJECT", "acc/../x", ".hidden", "-lead", "a;b", "acc‮", strings.Repeat("a", 129),
	} {
		f := newApprovalFixture(30)
		f.authz.allowAny = true // the policies are not what refuses it
		f.broker.WithApprovalNotifier(notifier)

		_, err := f.broker.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, bad, "ssh", goodReason, 20)
		if err == nil || !strings.Contains(err.Error(), "not well-formed") {
			t.Errorf("account %q: err=%v, want a refusal that says the identifier is not well-formed", bad, err)
			continue
		}
		if !f.audit.has("session.breakglass_requested", false) {
			t.Errorf("account %q: the refused attempt was not audited: %v", bad, f.audit.events)
		}
	}
	if notifier.count() != 0 {
		t.Fatalf("a request that was refused was announced: %+v", notifier.got)
	}

	// The control: identifiers of the shape the platform issues are not in the way.
	for _, good := range []string{"a", "A", "7", "acc_01", "acc-prod.db:eu-1", strings.Repeat("a", 128)} {
		f := newApprovalFixture(30)
		f.authz.allowAny = true
		if _, err := f.broker.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, good, "ssh", goodReason, 20); err != nil {
			t.Errorf("account %q was refused: %v", good, err)
		}
	}
}

// -- the notification --------------------------------------------------------------------

type recordingNotifier struct {
	mu     sync.Mutex
	got    []domain.ApprovalNotification
	onSend func(domain.ApprovalNotification)
}

func (n *recordingNotifier) Notify(ctx context.Context, nt domain.ApprovalNotification) {
	n.mu.Lock()
	n.got = append(n.got, nt)
	hook := n.onSend
	n.mu.Unlock()
	if hook != nil {
		hook(nt)
	}
}

func (n *recordingNotifier) count() int {
	n.mu.Lock()
	defer n.mu.Unlock()
	return len(n.got)
}

func TestNotify_ARequestIsAnnouncedOnceItIsSaved_WithWhatItNeeds(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	notifier := &recordingNotifier{}
	var savedWhenTold bool
	var sid string
	notifier.onSend = func(nt domain.ApprovalNotification) {
		got, err := f.store.Get(context.Background(), nt.SessionID)
		savedWhenTold = err == nil && got.Status == domain.StatusPendingApproval
		sid = nt.SessionID
	}
	f.broker.WithApprovalNotifier(notifier)

	sess := f.request(t)
	if notifier.count() != 1 {
		t.Fatalf("%d notifications, want 1", notifier.count())
	}
	nt := notifier.got[0]
	want := domain.ApprovalNotification{
		Event: domain.NotifyBreakGlassRequested, SessionID: sess.ID, AccountID: acct, RequestedBy: requester,
		DurationMinutes: 20, ExpiresAt: sess.ExpiresAt, At: f.clock.Now(),
	}
	if nt != want {
		t.Fatalf("notification = %+v\nwant           %+v", nt, want)
	}
	if !savedWhenTold || sid != sess.ID {
		t.Fatal("the announcement came before the request could be found: an approver told too early would find nothing")
	}
	if !nt.ExpiresAt.Equal(f.clock.Now().Add(application.DefaultBreakGlassApprovalWindow)) {
		t.Fatalf("the deadline announced is %v, want the end of the decision window", nt.ExpiresAt)
	}
}

func TestNotify_NothingIsAnnouncedForARequestThatDoesNotWait(t *testing.T) {
	cases := map[string]func() *approvalFixture{
		"no break-glass policy": func() *approvalFixture { return newApprovalFixture(30, sessionRes) },
		"break-glass off":       func() *approvalFixture { return newApprovalFixture(0, sessionRes, breakGlassRes) },
		"audit cannot write": func() *approvalFixture {
			f := newApprovalFixture(30, everything...)
			f.audit.failOn = "session.breakglass_requested"
			return f
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			f := build()
			notifier := &recordingNotifier{}
			f.broker.WithApprovalNotifier(notifier)
			if _, err := f.broker.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20); err == nil {
				t.Fatal("the request was granted")
			}
			if notifier.count() != 0 {
				t.Fatalf("announced: %+v", notifier.got)
			}
		})
	}

	// Without the double validation nothing waits: the grant is immediate, and there is
	// no one to ask.
	f := newApprovalFixture(30, everything...)
	f.broker = application.NewSessionBrokerService(f.store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithoutBreakGlassApproval().WithClock(f.clock.Now)
	notifier := &recordingNotifier{}
	f.broker.WithApprovalNotifier(notifier)
	if sess := f.request(t); sess.Status != domain.StatusActive {
		t.Fatalf("weak mode: %+v", sess)
	}
	if notifier.count() != 0 {
		t.Fatalf("a request that was granted at once was announced as waiting: %+v", notifier.got)
	}
}

func TestNotify_ADecisionIsAnnouncedOnceTaken(t *testing.T) {
	for _, c := range []struct {
		name   string
		decide func(f *approvalFixture, id string) (*domain.Session, error)
		event  string
		endsAt func(f *approvalFixture) time.Time
	}{
		{"approved", func(f *approvalFixture, id string) (*domain.Session, error) { return f.approve(id, approver) },
			domain.NotifyBreakGlassApproved, func(f *approvalFixture) time.Time { return f.clock.Now().Add(20 * time.Minute) }},
		{"rejected", func(f *approvalFixture, id string) (*domain.Session, error) { return f.reject(id, approver) },
			domain.NotifyBreakGlassRejected, func(f *approvalFixture) time.Time {
				return f.clock.Now().Add(application.DefaultBreakGlassApprovalWindow)
			}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := newApprovalFixture(30, everything...)
			sess := f.request(t)
			notifier := &recordingNotifier{}
			f.broker.WithApprovalNotifier(notifier)

			if _, err := c.decide(f, sess.ID); err != nil {
				t.Fatal(err)
			}
			if notifier.count() != 1 {
				t.Fatalf("%d notifications, want 1", notifier.count())
			}
			nt := notifier.got[0]
			if nt.Event != c.event || nt.SessionID != sess.ID || nt.AccountID != acct || nt.RequestedBy != requester ||
				nt.DecidedBy != approver || nt.DurationMinutes != 20 || !nt.At.Equal(f.clock.Now()) {
				t.Fatalf("notification = %+v", nt)
			}
			if !nt.ExpiresAt.Equal(c.endsAt(f)) {
				t.Fatalf("ExpiresAt = %v, want %v", nt.ExpiresAt, c.endsAt(f))
			}
		})
	}
}

func TestNotify_NothingIsAnnouncedForADecisionThatDidNotHappen(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	sess := f.request(t)
	notifier := &recordingNotifier{}
	f.broker.WithApprovalNotifier(notifier)
	quiet := func(what string) {
		t.Helper()
		if notifier.count() != 0 {
			t.Fatalf("%s: announced %+v", what, notifier.got)
		}
	}

	if _, err := f.approve(sess.ID, requester); err == nil {
		t.Fatal("self-approval")
	}
	quiet("a self-approval that was refused")

	f.authz.mu.Lock()
	delete(f.authz.allow, approveRes)
	f.authz.mu.Unlock()
	if _, err := f.approve(sess.ID, approver); err == nil {
		t.Fatal("approval without a policy")
	}
	quiet("an approval without authority")

	f.authz.mu.Lock()
	f.authz.allow[approveRes] = true
	f.authz.mu.Unlock()
	f.audit.failOn = "session.breakglass_approved"
	if _, err := f.approve(sess.ID, approver); err == nil {
		t.Fatal("approval with the audit down")
	}
	quiet("an approval that the audit could not record")
	f.audit.stopFailing()

	// A decision that loses the race to another is announced by the winner only: the
	// store swaps for nobody here.
	racing := &swapLosingStore{InMemoryStore: f.store}
	loser := application.NewSessionBrokerService(racing, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithClock(f.clock.Now).WithApprovalNotifier(notifier)
	if _, err := loser.ApproveBreakGlass(context.Background(), sess.ID, approver, []string{"lead"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("lost race: err=%v", err)
	}
	quiet("a decision that lost the compare-and-swap")

	// The control: the same request, decided properly, is announced.
	if _, err := f.approve(sess.ID, approver); err != nil {
		t.Fatal(err)
	}
	if notifier.count() != 1 {
		t.Fatalf("the decision that was taken must be announced once, got %d", notifier.count())
	}
}

type swapLosingStore struct{ *infrastructure.InMemoryStore }

func (swapLosingStore) SaveIfStatus(context.Context, *domain.Session, domain.SessionStatus) (bool, error) {
	return false, nil
}

// A notification travels to a channel read by people who may not be allowed to read a
// justification. That is a property of the shape of the message, so the shape is
// pinned: adding a field to it is a decision, and this test is where it is taken.
func TestNotification_HasNoFieldForAJustificationOrAnythingAboutTheTarget(t *testing.T) {
	typ := reflect.TypeOf(domain.ApprovalNotification{})
	var fields []string
	for i := 0; i < typ.NumField(); i++ {
		fields = append(fields, typ.Field(i).Name)
	}
	sort.Strings(fields)
	// Ticket (ADR-0067): a reference in the declared format, shown to the approver; the
	// justification stays out.
	want := []string{"AccountID", "At", "DecidedBy", "DurationMinutes", "Event", "ExpiresAt", "RequestedBy", "SessionID", "Ticket"}
	if !reflect.DeepEqual(fields, want) {
		t.Fatalf("ApprovalNotification has the fields %v, want %v — a new field is a new thing told to a channel (ADR-0012, rule 7)", fields, want)
	}
}

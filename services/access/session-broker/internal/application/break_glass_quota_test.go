package application_test

// The quota of break-glass requests waiting per requester (ADR-0013): one identity
// cannot drown the list and the channel the approvers read, nobody can use it to block
// somebody else, and it holds when requests race for the last place.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func (f *approvalFixture) tryRequest(by string) (*domain.Session, error) {
	return f.broker.CreateBreakGlassSession(context.Background(), by, []string{"sre"}, acct, "ssh", goodReason, 20)
}

// The default is the strict one, and it is what a Broker built by hand gets.
func TestQuota_ARequesterHoldsAtMostThreeWaiting_ByDefault(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	notifier := &recordingNotifier{}
	f.broker.WithApprovalNotifier(notifier)

	for i := 0; i < application.DefaultMaxPendingPerRequester; i++ {
		f.request(t)
	}
	if application.DefaultMaxPendingPerRequester != 3 {
		t.Fatalf("the default is %d, ADR-0013 says 3", application.DefaultMaxPendingPerRequester)
	}
	told := len(notifier.got)

	refused, err := f.tryRequest(requester)
	if !errors.Is(err, domain.ErrTooManyPending) || refused != nil {
		t.Fatalf("fourth request: %v, %v; want ErrTooManyPending", refused, err)
	}
	if !strings.Contains(err.Error(), "at most 3") {
		t.Fatalf("the refusal does not say the limit: %v", err)
	}
	if items, total, _ := f.list(t, approver, 1, 20); len(items) != 3 || total != 3 {
		t.Fatalf("the approver sees %d requests (%d), want the 3 that were accepted", len(items), total)
	}
	if len(notifier.got) != told {
		t.Fatal("a refused request was announced to the channel")
	}
}

// A refusal is audited like every other refusal, before anything was written as accepted.
func TestQuota_TheRefusalIsAudited_AndTheRequestWasNeverAnnouncedAsAccepted(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for i := 0; i < 3; i++ {
		f.request(t)
	}
	before := len(f.audit.events)
	if _, err := f.tryRequest(requester); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("err=%v", err)
	}
	got := f.audit.events[before:]
	if len(got) != 1 || got[0].action != "session.breakglass_requested" || got[0].success || got[0].actor != requester {
		t.Fatalf("audit after the refusal = %+v, want exactly one session.breakglass_requested with success=false", got)
	}
}

func TestQuota_IsPerRequester_SoNobodyCanBlockSomebodyElse(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for i := 0; i < 3; i++ {
		f.request(t)
	}
	if _, err := f.tryRequest(requester); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("the requester was not at the limit: %v", err)
	}
	// Somebody else, with the same authority, is not affected by the first one's queue.
	for i := 0; i < 3; i++ {
		if _, err := f.tryRequest("another-oncall"); err != nil {
			t.Fatalf("another requester's request %d was refused: %v", i+1, err)
		}
	}
	if _, err := f.tryRequest("another-oncall"); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("another requester has a quota of its own, and it is 3: %v", err)
	}
}

// What frees a place: a decision (either way) and the passing of the deadline.
func TestQuota_APlaceIsFreedByADecision_ByARejection_AndByTheDeadline(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	a, b, c := f.request(t), f.request(t), f.request(t)

	if _, err := f.approve(a.ID, approver); err != nil {
		t.Fatal(err)
	}
	if _, err := f.tryRequest(requester); err != nil {
		t.Fatalf("an approved request still holds a place: %v", err)
	}
	if _, err := f.tryRequest(requester); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("one place freed, two taken: %v", err)
	}

	if _, err := f.reject(b.ID, approver); err != nil {
		t.Fatal(err)
	}
	if _, err := f.tryRequest(requester); err != nil {
		t.Fatalf("a rejected request still holds a place: %v", err)
	}
	_ = c

	// The rest wait for their deadline: past it they are not waiting any more.
	if _, err := f.tryRequest(requester); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("full again, want a refusal: %v", err)
	}
	f.clock.advance(16 * time.Minute) // the window is 15
	if _, err := f.tryRequest(requester); err != nil {
		t.Fatalf("requests past their deadline still hold places: %v", err)
	}
}

// At the very instant of the deadline a request is still waiting (the same edge as the
// list and the decision) — a place is not freed a moment early.
func TestQuota_ARequestAtItsVeryDeadlineStillHoldsItsPlace(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for i := 0; i < 3; i++ {
		f.request(t)
	}
	f.clock.advance(application.DefaultBreakGlassApprovalWindow) // now == the deadline of all three
	if _, err := f.tryRequest(requester); !errors.Is(err, domain.ErrTooManyPending) {
		t.Fatalf("at the deadline itself: %v, want the places still held", err)
	}
	f.clock.advance(time.Nanosecond)
	if _, err := f.tryRequest(requester); err != nil {
		t.Fatalf("a nanosecond after the deadline: %v, want the places freed", err)
	}
}

func TestQuota_IsConfigurable_AndZeroOrNegativeKeepsTheStrictDefault(t *testing.T) {
	for _, c := range []struct{ set, allowed int }{{1, 1}, {2, 2}, {5, 5}, {0, 3}, {-4, 3}} {
		t.Run(fmt.Sprintf("set %d", c.set), func(t *testing.T) {
			f := newApprovalFixture(30, everything...)
			f.broker.WithMaxPendingPerRequester(c.set)
			for i := 0; i < c.allowed; i++ {
				if _, err := f.tryRequest(requester); err != nil {
					t.Fatalf("request %d of %d: %v", i+1, c.allowed, err)
				}
			}
			_, err := f.tryRequest(requester)
			if !errors.Is(err, domain.ErrTooManyPending) {
				t.Fatalf("request %d: %v, want the quota of %d to refuse it", c.allowed+1, err, c.allowed)
			}
			if want := fmt.Sprintf("at most %d", c.allowed); !strings.Contains(err.Error(), want) {
				t.Fatalf("the refusal says %q, want it to say %q", err.Error(), want)
			}
		})
	}
}

// Without approval nothing waits, so there is no queue to drown.
func TestQuota_DoesNotApplyWhereNothingWaits(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	f.broker.WithoutBreakGlassApproval()
	for i := 0; i < 6; i++ {
		if _, err := f.tryRequest(requester); err != nil {
			t.Fatalf("request %d without approval: %v", i+1, err)
		}
	}
}

// The weak mode starts after a Broker that required approval: requests may have been
// left waiting. They are nobody's queue any more (nothing is waiting for a decision that
// could free a place), so they must not turn a granted emergency into a refusal.
func TestQuota_RequestsLeftWaitingByAStricterModeDoNotBlockTheWeakMode(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for i := 0; i < 3; i++ {
		f.request(t) // the requester's queue is full under the strict mode
	}
	f.broker.WithoutBreakGlassApproval()
	sess, err := f.tryRequest(requester)
	if err != nil || sess.Status != domain.StatusActive {
		t.Fatalf("weak mode, three left waiting: %v, %v; want it granted", sess, err)
	}
}

// And the weak mode does not even ask: a queue that cannot be counted is no reason to
// refuse a request that would not wait in it.
func TestQuota_TheWeakModeDoesNotDependOnCountingAnything(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	store := countFailingStore{infrastructure.NewInMemoryStore()}
	svc := application.NewSessionBrokerService(store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithoutBreakGlassApproval().WithClock(f.clock.Now)
	sess, err := svc.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20)
	if err != nil || sess == nil || sess.Status != domain.StatusActive {
		t.Fatalf("weak mode with a store that cannot count: %v, %v; want it granted", sess, err)
	}
}

// Only a person who may request learns anything from the quota.
func TestQuota_IsOnlyToldToWhoMayRequest(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	for i := 0; i < 3; i++ {
		f.request(t)
	}
	f.authz.mu.Lock()
	delete(f.authz.allow, breakGlassRes) // the policy is withdrawn while three requests wait
	f.authz.mu.Unlock()
	_, err := f.tryRequest(requester)
	if err == nil || errors.Is(err, domain.ErrTooManyPending) || !strings.Contains(err.Error(), "no break-glass policy allows this") {
		t.Fatalf("err=%v, want the policy refusal — the quota is not for someone who may not request", err)
	}
}

// ---- failing closed, and the race ---------------------------------------------------

type countFailingStore struct{ *infrastructure.InMemoryStore }

func (countFailingStore) CountPending(context.Context, string, time.Time) (int, error) {
	return 0, errors.New("database unreachable: postgres://secret@10.0.0.7")
}

// A request that cannot be counted is not accepted, and what is said does not carry the
// cause (it can name an address).
func TestQuota_FailsClosedWhenTheRequestsWaitingCannotBeCounted(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	store := countFailingStore{infrastructure.NewInMemoryStore()}
	svc := application.NewSessionBrokerService(store, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithClock(f.clock.Now)

	sess, err := svc.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20)
	if !errors.Is(err, domain.ErrUnavailable) || sess != nil {
		t.Fatalf("got %v, %v; want ErrUnavailable and no session", sess, err)
	}
	if errors.Is(err, domain.ErrTooManyPending) {
		t.Fatal("a store that cannot count must not be reported as a full quota")
	}
	if items, _, _ := store.ListPending(context.Background(), f.clock.Now(), 10); len(items) != 0 {
		t.Fatalf("a request was left waiting: %v", ids(items))
	}
}

// staleCountStore says there is always room: it is the Broker that counted a moment
// before another request took the last place. SaveIfUnderPendingLimit is what is left.
type staleCountStore struct{ *infrastructure.InMemoryStore }

func (staleCountStore) CountPending(context.Context, string, time.Time) (int, error) { return 0, nil }

func TestQuota_TheLimitHoldsWhenTheCountSaidThereWasRoom(t *testing.T) {
	f := newApprovalFixture(30, everything...)
	inner := infrastructure.NewInMemoryStore()
	svc := application.NewSessionBrokerService(staleCountStore{inner}, f.authz, f.vault, f.audit, &fakeAccountLookup{}, f.proxy).
		WithBreakGlass(30).WithClock(f.clock.Now)
	notifier := &recordingNotifier{}
	svc.WithApprovalNotifier(notifier)

	for i := 0; i < 3; i++ {
		if _, err := svc.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20); err != nil {
			t.Fatalf("request %d: %v", i+1, err)
		}
	}
	told := len(notifier.got)
	auditBefore := len(f.audit.events)

	sess, err := svc.CreateBreakGlassSession(context.Background(), requester, []string{"sre"}, acct, "ssh", goodReason, 20)
	if !errors.Is(err, domain.ErrTooManyPending) || sess != nil {
		t.Fatalf("got %v, %v; want ErrTooManyPending from the atomic save", sess, err)
	}
	if n, _ := inner.CountPending(context.Background(), requester, f.clock.Now()); n != 3 {
		t.Fatalf("%d requests wait, want the 3 that fit", n)
	}
	if len(notifier.got) != told {
		t.Fatal("the request that lost the last place was announced")
	}
	// The audit says "requested", then — for the same session — that it was not accepted.
	ev := f.audit.events[auditBefore:]
	if len(ev) != 2 || !ev[0].success || ev[1].success || ev[0].resource != ev[1].resource ||
		ev[0].action != "session.breakglass_requested" || ev[1].action != "session.breakglass_requested" {
		t.Fatalf("audit = %+v, want requested(true) then requested(false) for the same session", ev)
	}
	// The lost request is kept as a denied attempt, like any refused one, and is not waiting.
	denied, err := inner.Get(context.Background(), ev[0].resource)
	if err != nil || denied.Status != domain.StatusDenied {
		t.Fatalf("the refused request is %v (%v), want it recorded as denied", denied, err)
	}
}

// The race itself: many requests of one requester at once take exactly the places left.
func TestQuota_ConcurrentRequestsTakeExactlyThePlacesThatAreLeft(t *testing.T) {
	for round := 0; round < 20; round++ {
		f := newApprovalFixture(30, everything...)
		const workers = 40
		var wg sync.WaitGroup
		var mu sync.Mutex
		accepted, refused, other := 0, 0, 0
		start := make(chan struct{})
		for i := 0; i < workers; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				_, err := f.tryRequest(requester)
				mu.Lock()
				defer mu.Unlock()
				switch {
				case err == nil:
					accepted++
				case errors.Is(err, domain.ErrTooManyPending):
					refused++
				default:
					other++
				}
			}()
		}
		close(start)
		wg.Wait()
		n, _ := f.store.CountPending(context.Background(), requester, f.clock.Now())
		if accepted != 3 || refused != workers-3 || other != 0 || n != 3 {
			t.Fatalf("round %d: accepted=%d refused=%d other=%d waiting=%d; want 3, %d, 0, 3", round, accepted, refused, other, n, workers-3)
		}
	}
}

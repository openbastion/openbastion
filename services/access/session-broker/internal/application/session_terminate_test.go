package application_test

// Who may end a session (ADR-0017): its requester, or somebody with a policy on
// session-terminate:account:{id}; the audit names the one who asked; the order is the
// session, then the caller, then the state; and a termination that nobody could authorise
// is not made.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const terminateRes = application.SessionTerminateResourcePrefix + acct

type terminateFixture struct {
	broker *application.SessionBrokerService
	authz  *resourceAuthz
	audit  *journalAudit
	store  *infrastructure.InMemoryStore
	clock  *fakeClock
}

func newTerminateFixture(allow ...string) *terminateFixture {
	return newTerminateFixtureOn(infrastructure.NewInMemoryStore(), allow...)
}

func newTerminateFixtureOn(store domain.SessionRepository, allow ...string) *terminateFixture {
	f := &terminateFixture{
		authz: &resourceAuthz{allow: map[string]bool{sessionRes: true}}, audit: &journalAudit{},
		clock: &fakeClock{t: time.Date(2026, 10, 26, 9, 0, 0, 0, time.UTC)},
	}
	for _, r := range allow {
		f.authz.allow[r] = true
	}
	if mem, ok := store.(*infrastructure.InMemoryStore); ok {
		f.store = mem
	}
	f.broker = application.NewSessionBrokerService(store, f.authz, &fakeVaultAuthorizer{}, f.audit, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithClock(f.clock.Now)
	return f
}

// open is an ordinary active session of `requester`.
func (f *terminateFixture) open(t *testing.T) *domain.Session {
	t.Helper()
	sess, err := f.broker.CreateSession(context.Background(), requester, []string{"sre"}, acct, "ssh", "ordinary maintenance", 30)
	if err != nil || sess.Status != domain.StatusActive {
		t.Fatalf("CreateSession: %+v, %v", sess, err)
	}
	return sess
}

func (f *terminateFixture) end(id, caller string, roles ...string) (*domain.Session, error) {
	return f.broker.TerminateSession(context.Background(), id, caller, roles)
}

// askedAbout says how many times the Authorization Service was asked about the
// termination resource.
func (f *terminateFixture) askedAbout(resource string) int {
	f.authz.mu.Lock()
	defer f.authz.mu.Unlock()
	n := 0
	for _, r := range f.authz.asked {
		if r == resource {
			n++
		}
	}
	return n
}

func (f *terminateFixture) actorOf(action string, success bool) (string, bool) {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	for _, e := range f.audit.events {
		if e.action == action && e.success == success {
			return e.actor, true
		}
	}
	return "", false
}

func (f *terminateFixture) statusOf(t *testing.T, id string) domain.SessionStatus {
	t.Helper()
	sess, err := f.store.Get(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	return sess.Status
}

func TestTerminate_TheRequesterEndsTheirOwnSession_WithNoPolicy_AndWithoutAskingAnyone(t *testing.T) {
	f := newTerminateFixture() // no policy to terminate for anybody
	f.authz.failOn = terminateRes
	sess := f.open(t)

	got, err := f.end(sess.ID, requester, "sre")
	if err != nil || got.Status != domain.StatusTerminated || got.TerminatedAt == nil {
		t.Fatalf("the requester ending their own session: %+v, %v", got, err)
	}
	if n := f.askedAbout(terminateRes); n != 0 {
		t.Fatalf("the Authorization Service was asked %d time(s): ending one's own access must not depend on it", n)
	}
	if actor, ok := f.actorOf("session.terminate", true); !ok || actor != requester {
		t.Fatalf("the success is attributed to %q (%v), want the requester", actor, ok)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusTerminated {
		t.Fatalf("stored status = %q", st)
	}
}

func TestTerminate_SomebodyWithNoPolicyIsRefused_UnderTheirOwnName_AndTheSessionIsUntouched(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)

	_, err := f.end(sess.ID, "stranger", "sre")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger ended the session, or was refused with another error: %v", err)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusActive {
		t.Fatalf("the session is %q after a refused termination", st)
	}
	if actor, ok := f.actorOf("session.terminate", false); !ok || actor != "stranger" {
		t.Fatalf("the refusal is attributed to %q (%v), want the stranger: the one who asked", actor, ok)
	}
	if f.audit.has("session.terminate", true) {
		t.Fatalf("a termination was audited as a success: %v", f.audit.events)
	}
	// It was asked on the termination resource, with the CALLER's roles — not the requester's.
	if f.askedAbout(terminateRes) != 1 || len(f.authz.askedRoles) == 0 || f.authz.askedRoles[len(f.authz.askedRoles)-1][0] != "sre" {
		t.Fatalf("asked %v with roles %v", f.authz.asked, f.authz.askedRoles)
	}
}

func TestTerminate_SomebodyWithThePolicyEndsItAndTheAuditNamesThem_NotTheRequester(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	sess := f.open(t)

	got, err := f.end(sess.ID, "responder-1", "responder")
	if err != nil || got.Status != domain.StatusTerminated {
		t.Fatalf("a person with the policy: %+v, %v", got, err)
	}
	if actor, ok := f.actorOf("session.terminate", true); !ok || actor != "responder-1" {
		t.Fatalf("the termination is attributed to %q (%v), want the responder: the requester did not end it", actor, ok)
	}
	if actor, _ := f.actorOf("session.terminate", true); actor == requester {
		t.Fatal("the audit names the requester as the author of somebody else's act")
	}
}

// The permission is its own resource: the others do not stand in for it.
func TestTerminate_TheOtherPoliciesAreNotThePolicyToTerminate(t *testing.T) {
	for name, res := range map[string]string{
		"to open a session":              sessionRes,
		"to ask for emergency":           breakGlassRes,
		"to approve an emergency":        approveRes,
		"to terminate on another":        application.SessionTerminateResourcePrefix + "another-account",
		"to terminate, as a bare prefix": application.SessionTerminateResourcePrefix,
	} {
		t.Run(name, func(t *testing.T) {
			f := newTerminateFixture(res)
			sess := f.open(t)
			if _, err := f.end(sess.ID, "somebody", "lead"); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("a policy %s ended the session: %v", name, err)
			}
			if st := f.statusOf(t, sess.ID); st != domain.StatusActive {
				t.Fatalf("the session is %q", st)
			}
		})
	}
}

func TestTerminate_WithoutACaller_NothingIsAskedAndNothingIsEnded(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	sess := f.open(t)
	asked := len(f.authz.asked)

	if _, err := f.end(sess.ID, "", "responder"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v, want a refusal", err)
	}
	if len(f.authz.asked) != asked {
		t.Fatalf("the Authorization Service was asked for nobody: %v", f.authz.asked)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusActive {
		t.Fatalf("the session is %q", st)
	}
	if f.audit.count("session.terminate") != 0 {
		t.Fatalf("an unauthenticated attempt was written under somebody's name: %v", f.audit.events)
	}
}

func TestTerminate_AnUnknownSessionIsNotFound_AndSaysNothingElse(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	asked := len(f.authz.asked)
	if _, err := f.end("session_nope", "responder-1", "responder"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown session: %v, want not found", err)
	}
	if len(f.authz.asked) != asked || f.audit.count("session.terminate") != 0 {
		t.Fatalf("an unknown session cost an Authorization question or an event: %v %v", f.authz.asked, f.audit.events)
	}
}

// The order is the session, the caller, the state: whoever has no authority is told
// "forbidden" whatever the state, so that the answer does not describe somebody else's
// session; whoever has it is told the state.
func TestTerminate_TheCallerComesBeforeTheState(t *testing.T) {
	f := newTerminateFixture() // nobody but the requester may end a session — yet
	sess := f.open(t)
	if _, err := f.end(sess.ID, requester, "sre"); err != nil {
		t.Fatal(err)
	}
	before := f.audit.count("session.terminate")

	if _, err := f.end(sess.ID, "stranger", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger on a finished session: %v, want forbidden (not a description of its state)", err)
	}
	f.authz.allow[terminateRes] = true // now an authority exists
	for who, caller := range map[string]string{"the requester": requester, "an authority": "responder-1"} {
		if _, err := f.end(sess.ID, caller, "responder"); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("%s on a finished session: %v, want a conflict", who, err)
		}
	}
	// One event for the refusal of the stranger; none for the conflicts.
	if n := f.audit.count("session.terminate") - before; n != 1 {
		t.Fatalf("%d events after one refusal and two conflicts, want 1: %v", n, f.audit.events)
	}
}

func TestTerminate_AnExpiredSessionIsAConflict_NotAnEvent(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	f.clock.advance(2 * time.Hour)
	before := f.audit.count("session.terminate")
	if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("an expired session: %v, want a conflict", err)
	}
	if f.audit.count("session.terminate") != before {
		t.Fatal("a conflict was written as an event")
	}
}

// A termination that nobody could authorise is not made — and says so as a dependency
// that is not answering, not as a refusal of the person.
func TestTerminate_FailsClosedWhenTheAuthorizationServiceDoesNotAnswer(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	f.authz.failOn = terminateRes
	sess := f.open(t)

	_, err := f.end(sess.ID, "responder-1", "responder")
	if !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("an unreachable Authorization Service: %v, want unavailable (and not a refusal)", err)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusActive {
		t.Fatalf("the session is %q: it was ended on an authority nobody could consult", st)
	}
	if f.audit.count("session.terminate") != 0 {
		t.Fatalf("an event was written for a question nobody could answer: %v", f.audit.events)
	}
}

// Ending a session reduces access: the success event is written at best, and an audit
// that is down does not keep a session open. A refusal stays a refusal whatever the audit does.
func TestTerminate_AnAuditThatIsDownDoesNotKeepASessionOpen_NorTurnARefusalIntoAnAllow(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	f.audit.failOn = "session.terminate"

	if _, err := f.end(sess.ID, "stranger", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger with the audit down: %v, want forbidden", err)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusActive {
		t.Fatalf("the session is %q", st)
	}
	if _, err := f.end(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the requester ending their session with the audit down: %v, want it ended", err)
	}
	if st := f.statusOf(t, sess.ID); st != domain.StatusTerminated {
		t.Fatalf("the session is %q: an audit that is down kept it open", st)
	}
}

type getFailingStore struct{ *infrastructure.InMemoryStore }

func (getFailingStore) Get(context.Context, string) (*domain.Session, error) {
	return nil, errors.New("database unreachable")
}

type saveFailingStore struct{ *infrastructure.InMemoryStore }

func (saveFailingStore) SaveIfStatus(context.Context, *domain.Session, domain.SessionStatus) (bool, error) {
	return false, errors.New("database unreachable")
}

func TestTerminate_ADatabaseThatDoesNotAnswerIsUnavailable_NotNotFound_AndNothingIsWritten(t *testing.T) {
	t.Run("reading", func(t *testing.T) {
		f := newTerminateFixtureOn(getFailingStore{infrastructure.NewInMemoryStore()})
		if _, err := f.end("session_x", requester, "sre"); !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("a read that failed: %v, want unavailable and not 'not found'", err)
		}
	})
	t.Run("saving", func(t *testing.T) {
		mem := infrastructure.NewInMemoryStore()
		f := newTerminateFixtureOn(saveFailingStore{mem})
		sess := f.open(t)
		if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("a save that failed: %v, want unavailable", err)
		}
		if f.audit.has("session.terminate", true) {
			t.Fatal("a termination that was not saved was audited as made")
		}
	})
}

// Two people who end the same session at once: one wins and is named; the other is told
// it is over, and no second success event is written.
func TestTerminate_ALostRaceIsAConflict_AndWritesNoSuccessEvent(t *testing.T) {
	f := newTerminateFixtureOn(swapLosingStore{infrastructure.NewInMemoryStore()})
	sess := f.open(t)
	if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("a termination that lost the race: %v, want a conflict", err)
	}
	if f.audit.has("session.terminate", true) {
		t.Fatalf("the loser of a race was written as having ended the session: %v", f.audit.events)
	}
}

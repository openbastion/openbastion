package application_test

// Ending a session is cutting it (ADR-0018): the proxy is told BEFORE the record changes, only
// for a termination that is authorised, with the time the session had left; if it cannot be
// told nothing is ended, the attempt is on the record under the caller's name, and the same
// call works once the proxy answers.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func TestTerminate_TheProxyIsToldBeforeTheRecordChanges_WithTheTimeTheSessionHadLeft(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t) // 30 minutes
	var statusWhenTold domain.SessionStatus
	f.proxy.onRevoke = func(id string) { statusWhenTold = f.statusOf(t, id) }
	f.clock.t = f.clock.t.Add(10 * time.Minute) // 20 minutes left

	if _, err := f.end(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("termination: %v", err)
	}
	if f.proxy.revokeCalls != 1 || f.proxy.revokedSessions[0] != sess.ID {
		t.Fatalf("the proxy was told %d times, about %v; want once, about %s", f.proxy.revokeCalls, f.proxy.revokedSessions, sess.ID)
	}
	if statusWhenTold != domain.StatusActive {
		t.Fatalf("the record said %q when the proxy was told: it must still be active, or a failure to tell would leave a session marked ended and open", statusWhenTold)
	}
	// The 20 minutes left plus a one-minute margin, written out: a margin that shrinks to
	// nothing would pass a test that computed its expectation from the constant.
	if want := 21 * time.Minute; f.proxy.revokedFor[0] != want {
		t.Fatalf("the proxy was told to remember for %v, want %v (the 20 minutes left and a one-minute margin)", f.proxy.revokedFor[0], want)
	}
	if got := f.statusOf(t, sess.ID); got != domain.StatusTerminated {
		t.Fatalf("the session is %q after a termination, want terminated", got)
	}
}

// The moment of the termination is the one at which the record changes, not the one at which
// the Broker began: the proxy may take its time to answer.
func TestTerminate_TheTerminationIsDatedWhenTheRecordChanges_NotWhenTheProxyWasAsked(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	f.proxy.onRevoke = func(string) { f.clock.t = f.clock.t.Add(7 * time.Second) } // a slow proxy

	ended, err := f.end(sess.ID, requester, "sre")
	if err != nil {
		t.Fatalf("termination: %v", err)
	}
	if ended.TerminatedAt == nil || !ended.TerminatedAt.Equal(f.clock.t) {
		t.Fatalf("terminated at %v, want %v: the moment the proxy answered", ended.TerminatedAt, f.clock.t)
	}
}

// An authority who cannot cut the session is on the record under their own name, not the
// requester's: the failed attempt is theirs.
func TestTerminate_AnAuthoritysFailedAttemptIsUnderTheirName(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	sess := f.open(t)
	f.proxy.revokeErr = errors.New("connection refused")

	if _, err := f.end(sess.ID, "responder", "responder"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("%v, want unavailable", err)
	}
	if actor, ok := f.actorOf("session.terminate", false); !ok || actor != "responder" {
		t.Fatalf("the failed attempt: actor %q found=%v, want %q, not the requester (%q)", actor, ok, "responder", requester)
	}
}

func TestTerminate_AnAuthorityIsToldTheSameWay(t *testing.T) {
	f := newTerminateFixture(terminateRes)
	sess := f.open(t)
	if _, err := f.end(sess.ID, "responder", "responder"); err != nil {
		t.Fatalf("termination by an authority: %v", err)
	}
	if f.proxy.revokeCalls != 1 {
		t.Fatalf("the proxy was told %d times, want once", f.proxy.revokeCalls)
	}
}

// If the proxy cannot be told, the session is not ended — and the caller is told so, plainly,
// rather than being given a "terminated" that leaves a connection open.
func TestTerminate_IfTheProxyCannotBeToldNothingIsEnded_TheAttemptIsOnTheRecord_AndTheSameCallWorksLater(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	f.proxy.revokeErr = errors.New("dial tcp 10.9.8.7:8082: connection refused")

	_, err := f.end(sess.ID, requester, "sre")
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("with the proxy down: %v, want unavailable", err)
	}
	if got := f.statusOf(t, sess.ID); got != domain.StatusActive {
		t.Fatalf("the session is %q after a termination that could not cut it, want active", got)
	}
	if f.audit.has("session.terminate", true) {
		t.Fatal("a termination that could not be made was audited as a success")
	}
	if actor, ok := f.actorOf("session.terminate", false); !ok || actor != requester {
		t.Fatalf("the failed attempt: actor %q found=%v, want it on the record under the caller's name (%q)", actor, ok, requester)
	}

	f.proxy.revokeErr = nil // the proxy is back
	if _, err := f.end(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the same call with the proxy back: %v", err)
	}
	if got := f.statusOf(t, sess.ID); got != domain.StatusTerminated {
		t.Fatalf("the session is %q, want terminated", got)
	}
	if !f.audit.has("session.terminate", true) {
		t.Fatal("the termination that worked is not on the record")
	}
}

// The proxy is told only for a termination the caller may make, of a session that is active:
// a refusal, an unknown session, a session already over, an Authorization Service that does
// not answer — none of them reaches it.
func TestTerminate_TheProxyIsNeverToldForATerminationThatIsNotMade(t *testing.T) {
	t.Run("a caller with no right", func(t *testing.T) {
		f := newTerminateFixture()
		sess := f.open(t)
		if _, err := f.end(sess.ID, "mallory", "sre"); !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("%v, want forbidden", err)
		}
		if f.proxy.revokeCalls != 0 {
			t.Fatalf("the proxy was told to cut a session whose termination was refused (%d times)", f.proxy.revokeCalls)
		}
	})
	t.Run("no caller", func(t *testing.T) {
		f := newTerminateFixture()
		sess := f.open(t)
		_, _ = f.end(sess.ID, "")
		if f.proxy.revokeCalls != 0 {
			t.Fatalf("the proxy was told %d times for a termination with no caller", f.proxy.revokeCalls)
		}
	})
	t.Run("an unknown session", func(t *testing.T) {
		f := newTerminateFixture()
		_, _ = f.end("session_nope", requester, "sre")
		if f.proxy.revokeCalls != 0 {
			t.Fatalf("the proxy was told %d times about a session that does not exist", f.proxy.revokeCalls)
		}
	})
	t.Run("a session already ended", func(t *testing.T) {
		f := newTerminateFixture()
		sess := f.open(t)
		if _, err := f.end(sess.ID, requester, "sre"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("a second termination: %v, want a conflict", err)
		}
		if f.proxy.revokeCalls != 1 {
			t.Fatalf("the proxy was told %d times, want once: a conflict is not a reason to ask it again", f.proxy.revokeCalls)
		}
	})
	t.Run("a session that expired", func(t *testing.T) {
		f := newTerminateFixture()
		sess := f.open(t)
		f.clock.t = f.clock.t.Add(time.Hour)
		if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrConflict) {
			t.Fatalf("%v, want a conflict", err)
		}
		if f.proxy.revokeCalls != 0 {
			t.Fatalf("the proxy was told %d times about a session that had expired by itself (the proxy cuts it at that moment)", f.proxy.revokeCalls)
		}
	})
	t.Run("an Authorization Service that does not answer", func(t *testing.T) {
		f := newTerminateFixture(terminateRes)
		f.authz.failOn = terminateRes
		sess := f.open(t)
		if _, err := f.end(sess.ID, "responder", "responder"); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("%v, want unavailable", err)
		}
		if f.proxy.revokeCalls != 0 {
			t.Fatalf("the proxy was told %d times for a termination nobody could authorise", f.proxy.revokeCalls)
		}
	})
}

// The proxy was told and then the record could not be changed: the session is cut but still
// marked active — the safe direction — and ending it again finishes the job.
func TestTerminate_ACutThatIsNotFollowedByTheRecordIsRetryable(t *testing.T) {
	mem := infrastructure.NewInMemoryStore()
	failing := &toggleSaveStore{InMemoryStore: mem, fail: true}
	f := newTerminateFixtureOn(failing)
	sess := f.open(t)

	if _, err := f.end(sess.ID, requester, "sre"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("%v, want unavailable", err)
	}
	if f.proxy.revokeCalls != 1 {
		t.Fatalf("the proxy was told %d times, want once", f.proxy.revokeCalls)
	}
	if got, _ := mem.Get(context.Background(), sess.ID); got.Status != domain.StatusActive {
		t.Fatalf("the record is %q, want it untouched", got.Status)
	}
	failing.fail = false
	if _, err := f.end(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the retry: %v", err)
	}
	if f.proxy.revokeCalls != 2 {
		t.Fatalf("the proxy was told %d times in all, want twice: the retry asks again, and the proxy treats it as idempotent", f.proxy.revokeCalls)
	}
	if got, _ := mem.Get(context.Background(), sess.ID); got.Status != domain.StatusTerminated {
		t.Fatalf("the record is %q after the retry, want terminated", got.Status)
	}
}

// toggleSaveStore refuses the compare-and-swap while `fail` is set.
type toggleSaveStore struct {
	*infrastructure.InMemoryStore
	fail bool
}

func (s *toggleSaveStore) SaveIfStatus(ctx context.Context, sess *domain.Session, from domain.SessionStatus) (bool, error) {
	if s.fail {
		return false, errors.New("database unreachable")
	}
	return s.InMemoryStore.SaveIfStatus(ctx, sess, from)
}

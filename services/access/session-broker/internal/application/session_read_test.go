package application_test

// Who may read a session (ADR-0019): its requester, always; the person who decided it; or
// somebody with a policy on session-read:account:{id}. The order is the session, then the
// caller; a read nobody could authorise is not served; a refusal tells nothing of the
// session; and reading writes nothing — to the audit or anywhere.

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

const readRes = application.SessionReadResourcePrefix + acct

func (f *terminateFixture) read(id, caller string, roles ...string) (*domain.Session, error) {
	return f.broker.GetSession(context.Background(), id, caller, roles)
}

func (f *terminateFixture) auditCount() int {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	return len(f.audit.events)
}

func TestRead_TheRequesterReadsTheirOwnSession_WithNoPolicy_AndWithoutAskingAnyone(t *testing.T) {
	f := newTerminateFixture() // no policy to read for anybody
	f.authz.failOn = readRes
	sess := f.open(t)

	got, err := f.read(sess.ID, requester, "sre")
	if err != nil || got.ID != sess.ID || got.RequestedBy != requester {
		t.Fatalf("the requester reading their own session: %+v, %v", got, err)
	}
	if n := f.askedAbout(readRes); n != 0 {
		t.Fatalf("the Authorization Service was asked %d time(s): reading one's own session must not depend on it", n)
	}
}

func TestRead_ASessionIsReadBySomebodyWithAPolicyOnItsAccount_AskedOnTheRightResourceWithTheirRoles(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)

	got, err := f.read(sess.ID, "auditor-1", "auditor", "sre")
	if err != nil || got.ID != sess.ID {
		t.Fatalf("somebody with a read policy: %+v, %v", got, err)
	}
	if n := f.askedAbout(readRes); n != 1 {
		t.Fatalf("asked about %s %d times, want once", readRes, n)
	}
	f.authz.mu.Lock()
	defer f.authz.mu.Unlock()
	last := f.authz.askedRoles[len(f.authz.askedRoles)-1]
	if len(last) != 2 || last[0] != "auditor" || last[1] != "sre" {
		t.Fatalf("the Authorization Service was asked with the roles %v, want the caller's own", last)
	}
}

func TestRead_ASessionIsRefusedToSomebodyWithNoRight_AndTheRefusalTellsNothingOfIt(t *testing.T) {
	f := newTerminateFixture() // nobody may read
	sess := f.open(t)

	_, err := f.read(sess.ID, "mallory", "sre")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger: %v, want forbidden", err)
	}
	// The reason the Authorization Service gives (resourceAuthz's "no policy matches this
	// resource…", which a real one words with the resource) is the operator's, not the caller's.
	for _, leak := range []string{acct, requester, "ordinary maintenance", sess.ID, string(domain.StatusActive), readRes, "no policy matches", "resource"} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the refusal says %q: %q", leak, err.Error())
		}
	}
	if n := f.askedAbout(readRes); n != 1 {
		t.Fatalf("a stranger: asked %d times, want once", n)
	}
}

// Opening, approving and ending are other powers: none of their policies reads a session.
func TestRead_TheOtherPoliciesAreNotThePolicyToRead(t *testing.T) {
	for name, res := range map[string]string{
		"to open a session":              sessionRes,
		"to request an emergency access": breakGlassRes,
		"to approve an emergency access": approveRes,
		"to end a session":               terminateRes,
	} {
		t.Run(name, func(t *testing.T) {
			f := newTerminateFixture(res)
			sess := f.open(t)
			if _, err := f.read(sess.ID, "somebody", "sre"); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("with only the policy %s: %v, want forbidden", res, err)
			}
		})
	}
}

// The requester is the exact name the Gateway wrote when the session was opened: a name that
// resembles it — longer, shorter, in capitals, padded — is somebody else, asked about the policy.
func TestRead_OnlyTheExactRequesterIsTheRequester(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	for name, caller := range map[string]string{
		"the name with something added": requester + "2",
		"a prefix of the name":          requester[:len(requester)-1],
		"the name in capitals":          strings.ToUpper(requester),
		"the name padded after":         requester + " ",
		"the name padded before":        " " + requester,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := f.read(sess.ID, caller, "sre"); !errors.Is(err, domain.ErrForbidden) {
				t.Fatalf("%q reading %q's session: %v, want forbidden", caller, requester, err)
			}
		})
	}
	if _, err := f.read(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the exact name: %v", err)
	}
}

func TestRead_ThePolicyIsOnTheAccountOfTheSession_NotAnother(t *testing.T) {
	f := newTerminateFixture(application.SessionReadResourcePrefix + "some-other-account")
	sess := f.open(t)
	if _, err := f.read(sess.ID, "auditor-1", "auditor"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a policy on another account: %v, want forbidden", err)
	}
}

func TestRead_ThePersonWhoDecidedASessionReadsIt_ButNotSomebodyElsesDecision(t *testing.T) {
	f := newTerminateFixture()
	f.authz.failOn = readRes
	decided, other := f.open(t), f.open(t)
	for id, decider := range map[string]string{decided.ID: "approver-1", other.ID: "approver-2"} {
		rec, _ := f.store.Get(context.Background(), id)
		cp := *rec
		cp.DecidedBy = decider
		if err := f.store.Save(context.Background(), &cp); err != nil {
			t.Fatal(err)
		}
	}
	if got, err := f.read(decided.ID, "approver-1", "lead"); err != nil || got.ID != decided.ID {
		t.Fatalf("the decider reading what they decided: %+v, %v", got, err)
	}
	if n := f.askedAbout(readRes); n != 0 {
		t.Fatalf("the Authorization Service was asked %d time(s) for the decider", n)
	}
	f.authz.failOn = "" // approver-1 is a stranger to the other session: asked, and refused
	if _, err := f.read(other.ID, "approver-1", "lead"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a decider reading somebody else's decision: %v, want forbidden", err)
	}
}

// A session nobody decided has no decider: a caller must not match an empty name.
func TestRead_ASessionNobodyDecidedHasNoDecider(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	if sess.DecidedBy != "" {
		t.Fatalf("setup: an ordinary session has a decider %q", sess.DecidedBy)
	}
	if _, err := f.read(sess.ID, "", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v, want forbidden", err)
	}
}

func TestRead_TheOrderIsTheSession_ThenTheCaller(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)

	if _, err := f.read("session_does_not_exist", "mallory", "sre"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown session: %v, want not found", err)
	}
	if _, err := f.read(sess.ID, "", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v, want forbidden: reading needs an authenticated user", err)
	}
	if _, err := f.read("session_does_not_exist", ""); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller, unknown session: %v, want forbidden", err)
	}
}

func TestRead_IfTheAuthorizationServiceDoesNotAnswerAStrangerIsNotServed_ButTheRequesterIs(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)
	f.authz.failOn = readRes

	if _, err := f.read(sess.ID, "auditor-1", "auditor"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Authorization down: %v, want unavailable (fail closed, and not a refusal)", err)
	}
	if _, err := f.read(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the requester with Authorization down: %v", err)
	}
}

func TestRead_ADatabaseThatDoesNotAnswerIsUnavailable_NotNotFound(t *testing.T) {
	f := newTerminateFixtureOn(&brokenReads{})
	if _, err := f.read("session_x", requester, "sre"); !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("a database that fails: %v, want unavailable", err)
	}
}

// brokenReads is a store whose reads fail.
type brokenReads struct{ domain.SessionRepository }

func (brokenReads) Get(context.Context, string) (*domain.Session, error) {
	return nil, errors.New("connection refused")
}

// A read that is served writes nothing — no event, no row — and neither does a session that
// is not found. The one thing a read writes is the refusal of somebody who may not read
// (ADR-0020): one event, under the name of the one who asked, and never the record.
func TestRead_AServedReadWritesNothing_AndOnlyARefusalIsOnTheRecord(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)
	before := f.auditCount()
	rec, _ := f.store.Get(context.Background(), sess.ID)
	stored := *rec

	_, _ = f.read(sess.ID, requester, "sre")       // served: the requester
	_, _ = f.read(sess.ID, "auditor-1", "auditor") // served: a policy
	_, _ = f.read("session_unknown", "mallory", "nope")
	if after := f.auditCount(); after != before {
		t.Fatalf("%d audit event(s) were written by reads that were served or found nothing", after-before)
	}

	f.authz.allow[readRes] = false
	_, _ = f.read(sess.ID, "mallory", "nope") // refused
	if after := f.auditCount(); after != before+1 {
		t.Fatalf("%d audit event(s) for one refused read, want 1", after-before)
	}
	now, _ := f.store.Get(context.Background(), sess.ID)
	if !reflect.DeepEqual(*now, stored) {
		t.Fatalf("a read changed the record: %+v -> %+v", stored, *now)
	}
}

func TestRead_ReflectsExpiry_ForTheOneWhoMayRead(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	f.clock.t = f.clock.t.Add(time.Hour)
	got, err := f.read(sess.ID, requester, "sre")
	if err != nil || got.Status != domain.StatusExpired {
		t.Fatalf("read after the deadline: %+v, %v, want expired", got, err)
	}
	if f.statusOf(t, sess.ID) != domain.StatusActive {
		t.Fatal("expiry must be read, not written")
	}
}

// writeCounter counts what is written to the store: a read that saved the record it just
// read — unchanged, so the comparison above would not see it — is still a write.
type writeCounter struct {
	*infrastructure.InMemoryStore
	writes int
}

func (w *writeCounter) Save(ctx context.Context, s *domain.Session) error {
	w.writes++
	return w.InMemoryStore.Save(ctx, s)
}

func (w *writeCounter) SaveIfStatus(ctx context.Context, s *domain.Session, expected domain.SessionStatus) (bool, error) {
	w.writes++
	return w.InMemoryStore.SaveIfStatus(ctx, s, expected)
}

func (w *writeCounter) SaveIfUnderPendingLimit(ctx context.Context, s *domain.Session, limit int, now time.Time) (bool, error) {
	w.writes++
	return w.InMemoryStore.SaveIfUnderPendingLimit(ctx, s, limit, now)
}

func TestRead_ReadingDoesNotWriteTheStoreAtAll(t *testing.T) {
	store := &writeCounter{InMemoryStore: infrastructure.NewInMemoryStore()}
	f := newTerminateFixtureOn(store, readRes)
	sess := f.open(t)
	if store.writes == 0 {
		t.Fatal("setup: opening a session wrote nothing, the counter counts nothing")
	}
	store.writes = 0

	_, _ = f.read(sess.ID, requester, "sre")       // the requester
	_, _ = f.read(sess.ID, "auditor-1", "auditor") // a policy
	f.authz.allow[readRes] = false
	_, _ = f.read(sess.ID, "mallory", "nope") // refused
	_, _ = f.read("session_unknown", "mallory", "nope")
	f.clock.t = f.clock.t.Add(time.Hour)
	_, _ = f.read(sess.ID, requester, "sre") // after the deadline

	if store.writes != 0 {
		t.Fatalf("reading wrote the store %d time(s)", store.writes)
	}
}

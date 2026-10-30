package application_test

// A read that is served to somebody who holds a policy is on the record (ADR-0021), under
// their name — and it is on the record BEFORE it is served: a read of a session that could
// not be recorded is not served. Serving it is what discloses the requester, the account, the
// justification of an emergency; unlike a refusal, which discloses nothing, nothing here is
// "best effort". The requester of a session and the person who decided it are not events:
// the first reads their own, the second has already seen it and their decision is on the
// record already.

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// readsServed is what the audit holds about reads that were served, in order.
func (f *terminateFixture) readsServed() []auditRecord {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var out []auditRecord
	for _, e := range f.audit.events {
		if e.action == "session.read" && e.success {
			out = append(out, e)
		}
	}
	return out
}

// decided is a session whose decision was taken by `by`.
func (f *terminateFixture) decided(t *testing.T, by string) *domain.Session {
	t.Helper()
	sess := f.open(t)
	rec, err := f.store.Get(context.Background(), sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	cp := *rec
	cp.DecidedBy = by
	if err := f.store.Save(context.Background(), &cp); err != nil {
		t.Fatal(err)
	}
	return sess
}

func TestReadServed_APolicyHoldersReadIsOnTheRecordUnderTheirName(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)

	if _, err := f.read(sess.ID, "auditor-1", "auditor"); err != nil {
		t.Fatalf("a policy holder: %v", err)
	}
	got := f.readsServed()
	if len(got) != 1 {
		t.Fatalf("%d event(s) for a served read, want exactly one: %+v", len(got), got)
	}
	want := auditRecord{action: "session.read", success: true, actor: "auditor-1", resource: sess.ID}
	if got[0] != want {
		t.Fatalf("the event is %+v, want %+v — the author is the one who read, not the requester", got[0], want)
	}
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	if last := f.audit.types[len(f.audit.types)-1]; last != "session" {
		t.Fatalf("the event is about a %q, want a session", last)
	}
}

// What the person who asked for the session reads of it, and what the person who decided it
// reads again, are not events: nothing is disclosed to them that they did not have.
func TestReadServed_TheRequesterAndTheDeciderAreNotEvents(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)
	decided := f.decided(t, "approver-1")

	for i := 0; i < 3; i++ {
		if _, err := f.read(sess.ID, requester, "sre"); err != nil {
			t.Fatal(err)
		}
		if _, err := f.read(decided.ID, "approver-1", "lead"); err != nil {
			t.Fatal(err)
		}
	}
	if got := f.readsServed(); len(got) != 0 {
		t.Fatalf("%d event(s) for the reads of the requester and of the decider: %+v", len(got), got)
	}
	// ... and a policy holder who is ALSO the decider is the decider: no policy was used.
	f.authz.allow[readRes] = true
	if _, err := f.read(decided.ID, "approver-1", "auditor"); err != nil {
		t.Fatal(err)
	}
	if got := f.readsServed(); len(got) != 0 {
		t.Fatalf("a read by the decider became an event because the decider also holds a policy: %+v", got)
	}
}

// Every read served on the strength of a policy is an event: there is no budget that
// leaves one out, because an event that is left out is a read that nobody can prove. And
// the budget of ADR-0020, which bounds what REFUSALS write, is neither spent by these reads
// nor does it silence them.
func TestReadServed_EveryServedReadIsAnEvent_AndTheRefusalBudgetIsAnotherThing(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)

	const reads = 3 * application.DefaultReadAuditBurst
	for i := 0; i < reads; i++ {
		if _, err := f.read(sess.ID, "auditor-1", "auditor"); err != nil {
			t.Fatalf("read %d: %v", i, err)
		}
	}
	if got := len(f.readsServed()); got != reads {
		t.Fatalf("%d event(s) for %d served reads: a served read is never left out", got, reads)
	}
	if got := len(f.readRefusals()); got != 0 {
		t.Fatalf("%d refusal(s) written by reads that were served", got)
	}

	// The same person, refused more often than their refusal budget allows, and then served:
	// the refusal budget is spent, and the served read is on the record all the same.
	f.authz.allow[readRes] = false
	for i := 0; i < 2*application.DefaultReadAuditBurst; i++ {
		_, _ = f.read(sess.ID, "auditor-1", "auditor")
	}
	if got := len(f.readRefusals()); got != application.DefaultReadAuditBurst {
		t.Fatalf("%d refusal(s) written, want the burst of %d: the setup must have spent the refusal budget", got, application.DefaultReadAuditBurst)
	}
	f.authz.allow[readRes] = true
	if _, err := f.read(sess.ID, "auditor-1", "auditor"); err != nil {
		t.Fatal(err)
	}
	if got := len(f.readsServed()); got != reads+1 {
		t.Fatalf("%d served-read event(s), want %d: a spent refusal budget must not silence a served read", got, reads+1)
	}
}

// A read that cannot be recorded is not served. The caller is told only that a dependency is
// unavailable — not a refusal, so not "you may not read", and nothing of the session; the
// cause travels in the error for the HTTP handler to write to the Broker's log, as for every
// other dependency that does not answer (ADR-0019, rule 5).
func TestReadServed_APolicyHoldersReadIsNotServedWithoutItsEvent(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)
	f.audit.failOn = "session.read"

	got, err := f.read(sess.ID, "auditor-1", "auditor")
	if !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("with the audit down: %v, want unavailable — not served, and not a refusal", err)
	}
	if errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("an audit that is down was reported as a refusal: %v", err)
	}
	if got != nil {
		t.Fatalf("the session was handed over with its event unwritten: %+v", got)
	}
	if !strings.Contains(err.Error(), "audit unreachable") {
		t.Fatalf("the cause is not in the error, so it cannot reach the Broker's log: %q", err.Error())
	}
	for _, leak := range []string{sess.ID, acct, requester} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the answer tells the caller %q: %q", leak, err.Error())
		}
	}

	// It is refused only for as long as the audit is down: the same read goes through, and is
	// on the record, as soon as it can be.
	f.audit.stopFailing()
	if _, err := f.read(sess.ID, "auditor-1", "auditor"); err != nil {
		t.Fatalf("once the audit is back: %v", err)
	}
	if got := len(f.readsServed()); got != 1 {
		t.Fatalf("%d event(s), want 1: the read that was not served must leave no event", got)
	}
}

// Whoever does not depend on a policy does not depend on the audit either: the requester
// reads their own session, and the decider the one they decided, with the audit down.
func TestReadServed_TheRequesterAndTheDeciderDoNotNeedTheAudit(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	decided := f.decided(t, "approver-1")
	f.audit.failOn = "session.read"

	if _, err := f.read(sess.ID, requester, "sre"); err != nil {
		t.Fatalf("the requester with the audit down: %v", err)
	}
	if _, err := f.read(decided.ID, "approver-1", "lead"); err != nil {
		t.Fatalf("the decider with the audit down: %v", err)
	}
}

// A refusal stays what ADR-0020 made it — best effort, the same answer — with the audit
// down: the stricter rule is for what is DISCLOSED.
func TestReadServed_ARefusalStaysBestEffortWithTheAuditDown(t *testing.T) {
	captureLog(t)
	f := newTerminateFixture() // nobody may read
	sess := f.open(t)
	f.audit.failOn = "session.read"

	if _, err := f.read(sess.ID, "mallory", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a refusal with the audit down: %v, want forbidden (not unavailable)", err)
	}
}

// What is not served is not an event: a session that is not there, a caller nobody named, an
// Authorization Service that does not answer, a refusal (which is an event of ADR-0020's, not
// a read that was served).
func TestReadServed_NothingElseIsAServedRead(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)

	if _, err := f.read("session_does_not_exist", "auditor-1", "auditor"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown session: %v", err)
	}
	if _, err := f.read(sess.ID, "", "auditor"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v", err)
	}
	f.authz.failOn = readRes
	if _, err := f.read(sess.ID, "auditor-2", "auditor"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("Authorization down: %v", err)
	}
	f.authz.failOn = ""
	f.authz.allow[readRes] = false
	if _, err := f.read(sess.ID, "mallory", "nope"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a refusal: %v", err)
	}
	if got := f.readsServed(); len(got) != 0 {
		t.Fatalf("%d served-read event(s) for reads that were not served: %+v", len(got), got)
	}
}

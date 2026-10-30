package application_test

// A refused read of a session is on the record (ADR-0020), under the name of the one who
// asked — within a budget per identity, so that it is not a way to write without limit
// into the audit trail (the problem of ADR-0014 and ADR-0016). A read that is served, a
// session that does not exist and a dependency that does not answer are not refusals.

import (
	"bytes"
	"context"
	"errors"
	"log"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
)

// captureLog is what the Broker writes to its log while the test runs.
func captureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	previous := log.Writer()
	var out bytes.Buffer
	log.SetOutput(&out)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &out
}

// readRefusals is what the audit holds about refused reads, in order (the reads that were
// served are readsServed's, ADR-0021).
func (f *terminateFixture) readRefusals() []auditRecord {
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	var out []auditRecord
	for _, e := range f.audit.events {
		if e.action == "session.read" && !e.success {
			out = append(out, e)
		}
	}
	return out
}

func TestReadRefusal_IsOnTheRecordUnderTheNameOfWhoAsked(t *testing.T) {
	f := newTerminateFixture() // nobody may read
	sess := f.open(t)

	if _, err := f.read(sess.ID, "mallory", "sre"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("a stranger: %v, want forbidden", err)
	}
	got := f.readRefusals()
	if len(got) != 1 {
		t.Fatalf("%d event(s) for a refused read, want exactly one: %+v", len(got), got)
	}
	want := auditRecord{action: "session.read", success: false, actor: "mallory", resource: sess.ID}
	if got[0] != want {
		t.Fatalf("the event is %+v, want %+v — the author is the one who asked, not the requester", got[0], want)
	}
}

func TestReadRefusal_IsAboutASession_NotAnythingElse(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)
	_, _ = f.read(sess.ID, "mallory", "sre")
	f.audit.mu.Lock()
	defer f.audit.mu.Unlock()
	last := len(f.audit.events) - 1
	if f.audit.events[last].action != "session.read" || f.audit.types[last] != "session" {
		t.Fatalf("the event is about a %q, want a session", f.audit.types[last])
	}
}

// Only a refusal is an event: a read that is served, a session that is not found, a caller
// nobody named, and a dependency that does not answer are not.
func TestReadRefusal_OnlyARefusalIsAnEvent(t *testing.T) {
	f := newTerminateFixture(readRes)
	sess := f.open(t)
	decided := f.open(t)
	rec, _ := f.store.Get(context.Background(), decided.ID)
	cp := *rec
	cp.DecidedBy = "approver-1"
	if err := f.store.Save(context.Background(), &cp); err != nil {
		t.Fatal(err)
	}

	if _, err := f.read(sess.ID, requester, "sre"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.read(sess.ID, "auditor-1", "auditor"); err != nil { // a policy
		t.Fatal(err)
	}
	if _, err := f.read(decided.ID, "approver-1", "lead"); err != nil { // the decider
		t.Fatal(err)
	}
	if _, err := f.read("session_does_not_exist", "mallory", "sre"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("an unknown session: %v", err)
	}
	if _, err := f.read(sess.ID, "", "sre"); !errors.Is(err, domain.ErrForbidden) { // nobody named
		t.Fatalf("no caller: %v", err)
	}
	f.authz.failOn = readRes
	if _, err := f.read(sess.ID, "auditor-2", "auditor"); !errors.Is(err, domain.ErrUnavailable) { // Authorization down
		t.Fatalf("Authorization down: %v", err)
	}
	if got := f.readRefusals(); len(got) != 0 {
		t.Fatalf("%d event(s) for reads that were not refusals: %+v", len(got), got)
	}
	// ... and none of them used a token of anybody's budget.
	f.authz.failOn = ""
	f.authz.allow[readRes] = false
	for i := 0; i < application.DefaultReadAuditBurst; i++ {
		_, _ = f.read(sess.ID, "auditor-2", "auditor")
	}
	if got := len(f.readRefusals()); got != application.DefaultReadAuditBurst {
		t.Fatalf("%d refusals written, want the full burst of %d: reads that were served must not have spent it", got, application.DefaultReadAuditBurst)
	}
}

// A budget bounds what is WRITTEN — never what is answered: the refusal is the same, to the
// word, whether its event was written or not.
func TestReadRefusal_IsBoundedByTheDefaultBudget_AndTheAnswerIsTheSame(t *testing.T) {
	f := newTerminateFixture()
	sess := f.open(t)

	var first, last error
	for i := 0; i < 25; i++ {
		_, err := f.read(sess.ID, "mallory", "sre")
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("refusal %d: %v, want forbidden whatever the budget", i, err)
		}
		if i == 0 {
			first = err
		}
		last = err
	}
	if got := len(f.readRefusals()); got != application.DefaultReadAuditBurst {
		t.Fatalf("%d refusals written out of 25, want the burst of %d", got, application.DefaultReadAuditBurst)
	}
	if first.Error() != last.Error() {
		t.Fatalf("the refusal differs once the budget is spent: %q then %q", first, last)
	}

	// 6 a minute: one token every 10 s.
	f.clock.t = f.clock.t.Add(10 * time.Second)
	_, _ = f.read(sess.ID, "mallory", "sre")
	_, _ = f.read(sess.ID, "mallory", "sre")
	if got := len(f.readRefusals()); got != application.DefaultReadAuditBurst+1 {
		t.Fatalf("%d written 10 s later, want one more (%d)", got, application.DefaultReadAuditBurst+1)
	}
}

// The budget is the identity's own — not the session's, not the account's.
func TestReadRefusal_TheBudgetIsTheIdentitys_AcrossSessionsAndOthersAreNotAffected(t *testing.T) {
	f := newTerminateFixture()
	f.broker.WithReadRefusalAudit(3, 6)
	s1, s2 := f.open(t), f.open(t)

	for i := 0; i < 10; i++ {
		id := s1.ID
		if i%2 == 1 {
			id = s2.ID
		}
		_, _ = f.read(id, "mallory", "sre")
	}
	if got := len(f.readRefusals()); got != 3 {
		t.Fatalf("%d written for one identity across two sessions, want its burst of 3", got)
	}
	_, _ = f.read(s2.ID, "bob", "sre")
	got := f.readRefusals()
	if len(got) != 4 || got[3].actor != "bob" || got[3].resource != s2.ID {
		t.Fatalf("Bob's refusal was not written under his own budget: %+v", got)
	}
}

func TestReadRefusal_TheBudgetCanBeSet_AndWhatIsNotPositiveKeepsTheDefault(t *testing.T) {
	f := newTerminateFixture()
	f.broker.WithReadRefusalAudit(2, 60)
	if b, r := f.broker.ReadRefusalAudit(); b != 2 || r != 60 {
		t.Fatalf("the budget is %d and %d a minute, want 2 and 60", b, r)
	}
	sess := f.open(t)
	for i := 0; i < 5; i++ {
		_, _ = f.read(sess.ID, "mallory", "sre")
	}
	if got := len(f.readRefusals()); got != 2 {
		t.Fatalf("%d written with a burst of 2", got)
	}
	f.clock.t = f.clock.t.Add(time.Second) // 60 a minute: one a second
	_, _ = f.read(sess.ID, "mallory", "sre")
	if got := len(f.readRefusals()); got != 3 {
		t.Fatalf("%d written a second later at 60 a minute, want 3", got)
	}

	f.broker.WithReadRefusalAudit(0, -1)
	if b, r := f.broker.ReadRefusalAudit(); b != 10 || r != 6 {
		t.Fatalf("a budget that is not positive is %d and %d a minute, want the defaults 10 and 6", b, r)
	}
}

func TestReadRefusal_TheBudgetFollowsTheServicesClock(t *testing.T) {
	f := newTerminateFixture()
	f.broker.WithReadRefusalAudit(1, 6) // replaced AFTER the clock was set
	sess := f.open(t)
	_, _ = f.read(sess.ID, "mallory", "sre")
	_, _ = f.read(sess.ID, "mallory", "sre")
	f.clock.t = f.clock.t.Add(10 * time.Second)
	_, _ = f.read(sess.ID, "mallory", "sre")
	if got := len(f.readRefusals()); got != 2 {
		t.Fatalf("%d written, want 2: the budget must run on the service's clock, whichever way it was built", got)
	}
}

// An audit that is down changes nothing for the caller — the read is refused — and the
// operator is told, in the Broker's log, which refusal it could not write and why.
func TestReadRefusal_AnAuditThatIsDownDoesNotChangeTheRefusal_AndIsInTheLog(t *testing.T) {
	logged := captureLog(t)
	f := newTerminateFixture()
	sess := f.open(t)
	f.audit.failOn = "session.read"

	_, err := f.read(sess.ID, "mallory", "sre")
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("with the audit down: %v, want forbidden — a refusal needs no audit to stand", err)
	}
	for _, want := range []string{sess.ID, "mallory", "could not be audited", "audit unreachable"} {
		if !strings.Contains(logged.String(), want) {
			t.Fatalf("the log does not say %q: %q", want, logged.String())
		}
	}
	for _, leak := range []string{"audit unreachable", sess.ID, acct} {
		if strings.Contains(err.Error(), leak) {
			t.Fatalf("the refusal tells the caller %q: %q", leak, err.Error())
		}
	}
}

// What the log says about a budget that is spent is said once per episode — a prober does
// not choose how many lines the Broker writes.
func TestReadRefusal_ASpentBudgetIsInTheLogOncePerEpisode(t *testing.T) {
	f := newTerminateFixture()
	f.broker.WithReadRefusalAudit(2, 6)
	sess := f.open(t)
	logged := captureLog(t)

	for i := 0; i < 30; i++ {
		_, _ = f.read(sess.ID, "mallory", "sre")
	}
	const line = "refused reads by user mallory are no longer written to the audit one by one"
	if n := strings.Count(logged.String(), line); n != 1 {
		t.Fatalf("%d line(s) for a spent budget over 30 refusals, want 1: %q", n, logged.String())
	}
	for _, leak := range []string{sess.ID, acct, requester} {
		if strings.Contains(logged.String(), leak) {
			t.Fatalf("the line tells %q: %q", leak, logged.String())
		}
	}
	f.clock.t = f.clock.t.Add(10 * time.Second) // a token comes back: a new episode
	for i := 0; i < 5; i++ {
		_, _ = f.read(sess.ID, "mallory", "sre")
	}
	if n := strings.Count(logged.String(), line); n != 2 {
		t.Fatalf("%d lines after a second episode, want 2", n)
	}
	if strings.Contains(logged.String(), "bob") {
		t.Fatal("somebody else is named in the log")
	}
}

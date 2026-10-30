package application

import (
	"context"
	"errors"
	"log"
	"os"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
)

// fakeAuthz allows the "auditor" role and records what it was asked.
type fakeAuthz struct {
	err       error
	resources []string
	actions   []string
}

func (f *fakeAuthz) CheckAccess(ctx context.Context, actorRoles []string, resource, action string) (bool, string, error) {
	f.resources = append(f.resources, resource)
	f.actions = append(f.actions, action)
	if f.err != nil {
		return false, "", f.err
	}
	for _, r := range actorRoles {
		if r == "auditor" {
			return true, "allowed by policy", nil
		}
	}
	return false, "no matching allow policy", nil
}

// fakeAudit remembers the events it was given, and fails every one while err is set.
type fakeAudit struct {
	err    error
	events []auditEvent
}

type auditEvent struct {
	actor, action, resourceType, resourceID string
	success                                 bool
}

func (f *fakeAudit) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	if f.err != nil {
		return f.err
	}
	f.events = append(f.events, auditEvent{actorID, action, resourceType, resourceID, success})
	return nil
}

func newService() (*RecorderService, *infrastructure.InMemoryStore, *fakeAuthz) {
	svc, store, authz, _ := newAuditedService()
	return svc, store, authz
}

func newAuditedService() (*RecorderService, *infrastructure.InMemoryStore, *fakeAuthz, *fakeAudit) {
	store := infrastructure.NewInMemoryStore()
	authz := &fakeAuthz{}
	audit := &fakeAudit{}
	return NewRecorderService(store, authz, audit), store, authz, audit
}

// reader is the user the Gateway names as the one reading.
const reader = "u_carol"

var auditor = []string{"auditor"}

func entry(session, command string, at time.Time) domain.CommandEntry {
	return domain.CommandEntry{SessionID: session, Timestamp: at, Command: command}
}

func commandsOf(entries []domain.CommandEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.Command)
	}
	return out
}

func equal(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestRecord_StoresEntriesAndGetRecordingReturnsThemInOrder(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	t0 := time.Now().UTC()

	n, err := svc.Record(ctx, []domain.CommandEntry{
		entry("s1", "whoami", t0),
		entry("s1", "ls -la", t0.Add(time.Second)),
	})
	if err != nil || n != 2 {
		t.Fatalf("Record: n=%d err=%v", n, err)
	}

	got, total, err := svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	if err != nil {
		t.Fatalf("GetRecording: %v", err)
	}
	if total != 2 || !equal(commandsOf(got), []string{"whoami", "ls -la"}) {
		t.Fatalf("unexpected recording: total=%d %q", total, commandsOf(got))
	}
}

func TestRecord_RefusesTheWholeBatchIfAnyEntryIsInvalid(t *testing.T) {
	now := time.Now().UTC()
	cases := map[string][]domain.CommandEntry{
		"empty batch":        {},
		"no session id":      {entry("s1", "ok", now), entry("", "x", now)},
		"no timestamp":       {entry("s1", "ok", now), entry("s1", "x", time.Time{})},
		"empty command":      {entry("s1", "ok", now), entry("s1", "   ", now)},
		"only NUL bytes":     {entry("s1", "ok", now), entry("s1", "\x00\x00", now)},
		"session id too big": {entry(strings.Repeat("s", maxSessionIDBytes+1), "x", now)},
	}
	for name, batch := range cases {
		t.Run(name, func(t *testing.T) {
			svc, _, _ := newService()
			n, err := svc.Record(context.Background(), batch)
			if !errors.Is(err, domain.ErrInvalidEntry) || n != 0 {
				t.Fatalf("expected ErrInvalidEntry and 0 stored, got n=%d err=%v", n, err)
			}
			// All-or-nothing: the valid first entry must not have been kept.
			got, total, _ := svc.GetRecording(context.Background(), reader, auditor, "s1", 1, 20)
			if total != 0 || len(got) != 0 {
				t.Fatalf("part of a refused batch was stored: %q", commandsOf(got))
			}
		})
	}
}

func TestRecord_RefusesAnOversizedBatch(t *testing.T) {
	svc, _, _ := newService()
	batch := make([]domain.CommandEntry, MaxBatchSize+1)
	for i := range batch {
		batch[i] = entry("s1", "x", time.Now())
	}
	if _, err := svc.Record(context.Background(), batch); !errors.Is(err, domain.ErrInvalidEntry) {
		t.Fatalf("expected ErrInvalidEntry, got %v", err)
	}
}

func TestRecord_NormalizesAwkwardCommandsInsteadOfLosingThem(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	now := time.Now().UTC()

	// "a" shifts every "é" (2 bytes) onto an odd offset, so the cut at
	// MaxCommandBytes lands in the MIDDLE of a character and must back up.
	long := "a" + strings.Repeat("é", MaxCommandBytes)
	_, err := svc.Record(ctx, []domain.CommandEntry{
		entry("s1", "  padded  ", now),
		entry("s1", "bad\xffbytes", now.Add(time.Millisecond)),
		entry("s1", "nul\x00inside", now.Add(2*time.Millisecond)),
		entry("s1", long, now.Add(3*time.Millisecond)),
	})
	if err != nil {
		t.Fatalf("Record: %v", err)
	}
	got, _, _ := svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	cmds := commandsOf(got)
	if cmds[0] != "padded" {
		t.Fatalf("expected trimmed command, got %q", cmds[0])
	}
	if cmds[1] != "bad�bytes" {
		t.Fatalf("expected invalid UTF-8 replaced, got %q", cmds[1])
	}
	if cmds[2] != "nulinside" {
		t.Fatalf("expected NUL removed, got %q", cmds[2])
	}
	if !utf8.ValidString(cmds[3]) || len(cmds[3]) != MaxCommandBytes-1 {
		t.Fatalf("expected a valid-UTF-8 truncation backed up to %d bytes, got %d bytes (valid=%v)", MaxCommandBytes-1, len(cmds[3]), utf8.ValidString(cmds[3]))
	}
}

func TestGetRecording_OrdersByTimestampThenInsertion(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	t0 := time.Now().UTC()

	// Recorded out of timestamp order, with a tie on t0.
	_, _ = svc.Record(ctx, []domain.CommandEntry{
		entry("s1", "third", t0.Add(time.Second)),
		entry("s1", "first-a", t0),
		entry("s1", "first-b", t0),
	})
	got, _, _ := svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	if want := []string{"first-a", "first-b", "third"}; !equal(commandsOf(got), want) {
		t.Fatalf("expected %q, got %q", want, commandsOf(got))
	}
}

func TestGetRecording_OnlyReturnsTheRequestedSession(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("s1", "mine", now), entry("s2", "theirs", now)})

	got, total, _ := svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	if total != 1 || !equal(commandsOf(got), []string{"mine"}) {
		t.Fatalf("expected only s1's entry, got %q (total %d)", commandsOf(got), total)
	}
}

func TestGetRecording_AnEmptySessionIsAnEmptyPageNotAnError(t *testing.T) {
	svc, _, _ := newService()
	got, total, err := svc.GetRecording(context.Background(), reader, auditor, "no-such-session", 1, 20)
	if err != nil || total != 0 || got == nil || len(got) != 0 {
		t.Fatalf("expected an empty non-nil page, got %v total=%d err=%v", got, total, err)
	}
}

func TestGetRecording_PaginatesAndClamps(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	t0 := time.Now().UTC()
	var batch []domain.CommandEntry
	for i := 0; i < 25; i++ {
		batch = append(batch, entry("s1", "cmd-"+string(rune('a'+i)), t0.Add(time.Duration(i)*time.Second)))
	}
	_, _ = svc.Record(ctx, batch)

	page2, total, _ := svc.GetRecording(ctx, reader, auditor, "s1", 2, 10)
	if total != 25 || len(page2) != 10 || page2[0].Command != "cmd-k" {
		t.Fatalf("page 2 of size 10: total=%d len=%d first=%q", total, len(page2), page2[0].Command)
	}
	last, _, _ := svc.GetRecording(ctx, reader, auditor, "s1", 3, 10)
	if len(last) != 5 {
		t.Fatalf("expected the last page to hold 5, got %d", len(last))
	}
	beyond, total, _ := svc.GetRecording(ctx, reader, auditor, "s1", 9, 10)
	if len(beyond) != 0 || total != 25 {
		t.Fatalf("a page past the end must be empty with the real total, got %d entries total=%d", len(beyond), total)
	}

	// Clamping: page < 1 → 1; pageSize < 1 → 20; pageSize > 100 → 100.
	first, _, _ := svc.GetRecording(ctx, reader, auditor, "s1", 0, 0)
	if len(first) != 20 || first[0].Command != "cmd-a" {
		t.Fatalf("page 0 / size 0 must serve page 1 with the default size 20, got %d entries first=%q", len(first), first[0].Command)
	}
	if p, ps := ClampPage(-3, 1000); p != 1 || ps != 100 {
		t.Fatalf("ClampPage(-3, 1000) = (%d, %d), want (1, 100)", p, ps)
	}
}

func TestGetRecording_IsDeniedWithoutAuthorization(t *testing.T) {
	svc, _, authz := newService()
	ctx := context.Background()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("s1", "secret-ish", time.Now())})

	for _, roles := range [][]string{nil, {}, {"dba"}} {
		got, total, err := svc.GetRecording(ctx, reader, roles, "s1", 1, 20)
		if !errors.Is(err, domain.ErrForbidden) || got != nil || total != 0 {
			t.Fatalf("roles %v: expected ErrForbidden and no data, got %v total=%d err=%v", roles, got, total, err)
		}
	}
	if authz.resources[0] != "recording:session:s1" || authz.actions[0] != "recording:session:read" {
		t.Fatalf("RBAC was asked about %q / %q", authz.resources[0], authz.actions[0])
	}
}

// An Authorization Service that does not answer serves nothing (fail-closed), and is
// not called a refusal: it is a 503, the same read is served once it is back (ADR-0022).
func TestGetRecording_FailsClosedWhenAuthorizationIsUnreachable(t *testing.T) {
	svc, _, authz, audit := newAuditedService()
	_, _ = svc.Record(context.Background(), []domain.CommandEntry{entry("s1", "x", time.Now())})
	authz.err = errors.New("connection refused")

	got, total, err := svc.GetRecording(context.Background(), reader, auditor, "s1", 1, 20)
	if !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrForbidden) || got != nil || total != 0 {
		t.Fatalf("an unreachable Authorization Service must serve nothing, as unavailable: %v total=%d err=%v", got, total, err)
	}
	if len(audit.events) != 0 {
		t.Fatalf("a read that was not decided is on the record: %+v", audit.events)
	}
}

// 403 must not depend on whether the session exists, or the denial itself
// would let an unauthorized caller probe for session ids.
func TestGetRecording_DenialDoesNotRevealWhetherASessionHasEntries(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("exists", "x", time.Now())})

	_, _, errExisting := svc.GetRecording(ctx, reader, []string{"dba"}, "exists", 1, 20)
	_, _, errMissing := svc.GetRecording(ctx, reader, []string{"dba"}, "does-not-exist", 1, 20)
	if !errors.Is(errExisting, domain.ErrForbidden) || !errors.Is(errMissing, domain.ErrForbidden) {
		t.Fatalf("both must be forbidden, got %v / %v", errExisting, errMissing)
	}
}

// -- readiness (ADR-0008) -----------------------------------------------------------

type readinessStore struct {
	*infrastructure.InMemoryStore
	err error
}

func (r readinessStore) Ready(ctx context.Context) error { return r.err }

func TestRecorderService_Ready(t *testing.T) {
	ctx := context.Background()

	// A store with nothing to check (in-memory) is always ready.
	svc, _, _ := newService()
	if err := svc.Ready(ctx); err != nil {
		t.Fatalf("an in-memory store must be ready: %v", err)
	}

	// A store that can say it is not ready is believed.
	down := errors.New("database is read-only")
	svc = NewRecorderService(readinessStore{InMemoryStore: infrastructure.NewInMemoryStore(), err: down}, &fakeAuthz{}, &fakeAudit{})
	if err := svc.Ready(ctx); !errors.Is(err, down) {
		t.Fatalf("readiness must come from the store, got %v", err)
	}

	svc = NewRecorderService(readinessStore{InMemoryStore: infrastructure.NewInMemoryStore()}, &fakeAuthz{}, &fakeAudit{})
	if err := svc.Ready(ctx); err != nil {
		t.Fatalf("a ready store must be ready: %v", err)
	}
}

// -- every read of a recording is on the record before it is served (ADR-0022) ------

func TestGetRecording_EveryServedPageIsAnEventUnderTheReadersName(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	ctx := context.Background()
	t0 := time.Now().UTC()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("s1", "whoami", t0), entry("s1", "id", t0.Add(time.Second))})

	for page := 1; page <= 2; page++ {
		if got, _, err := svc.GetRecording(ctx, reader, auditor, "s1", page, 1); err != nil || len(got) != 1 {
			t.Fatalf("page %d: %q %v", page, commandsOf(got), err)
		}
	}
	want := auditEvent{actor: reader, action: "recording.read", resourceType: "session", resourceID: "s1", success: true}
	if len(audit.events) != 2 || audit.events[0] != want || audit.events[1] != want {
		t.Fatalf("events for two served pages: %+v, want twice %+v", audit.events, want)
	}
}

// The recorder does not know which sessions exist: an empty recording is served like
// any other, and is on the record like any other.
func TestGetRecording_AnEmptyRecordingIsAReadOnTheRecord(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	if got, total, err := svc.GetRecording(context.Background(), reader, auditor, "nothing-here", 1, 20); err != nil || total != 0 || len(got) != 0 {
		t.Fatalf("an empty recording: %q total=%d err=%v", commandsOf(got), total, err)
	}
	if len(audit.events) != 1 || audit.events[0].resourceID != "nothing-here" || !audit.events[0].success {
		t.Fatalf("events: %+v", audit.events)
	}
}

func TestGetRecording_IsNotServedWithoutTheAudit_AndIsOnceItIsBack(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	ctx := context.Background()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("s1", "cat /etc/shadow", time.Now())})

	audit.err = errors.New("audit service: connection refused")
	got, total, err := svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	if !errors.Is(err, domain.ErrUnavailable) || errors.Is(err, domain.ErrForbidden) || got != nil || total != 0 {
		t.Fatalf("with the audit down: %q total=%d err=%v, want nothing served and unavailable", commandsOf(got), total, err)
	}

	audit.err = nil
	got, total, err = svc.GetRecording(ctx, reader, auditor, "s1", 1, 20)
	if err != nil || total != 1 || len(got) != 1 {
		t.Fatalf("with the audit back: %q total=%d err=%v", commandsOf(got), total, err)
	}
	if len(audit.events) != 1 {
		t.Fatalf("%d event(s): the read that was not served must have left none", len(audit.events))
	}
}

// Who reads is the Gateway's verified user: without one there is nobody to put on the
// record, and nobody is asked anything.
func TestGetRecording_IsRefusedWithoutAName(t *testing.T) {
	svc, _, authz, audit := newAuditedService()
	_, _ = svc.Record(context.Background(), []domain.CommandEntry{entry("s1", "x", time.Now())})

	got, _, err := svc.GetRecording(context.Background(), "", auditor, "s1", 1, 20)
	if !errors.Is(err, domain.ErrForbidden) || got != nil {
		t.Fatalf("no name: %q %v, want forbidden", commandsOf(got), err)
	}
	if len(authz.resources) != 0 || len(audit.events) != 0 {
		t.Fatalf("a read with no name reached Authorization (%q) or the audit (%+v)", authz.resources, audit.events)
	}
}

func TestGetRecording_ARefusalIsNotAServedRead(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	_, _ = svc.Record(context.Background(), []domain.CommandEntry{entry("s1", "x", time.Now())})
	if _, _, err := svc.GetRecording(context.Background(), reader, []string{"dba"}, "s1", 1, 20); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
	// A refusal is an event of its own since ADR-0024 (success=false); it is never a served read.
	for _, e := range audit.events {
		if e.success {
			t.Fatalf("a refusal was written as a served read: %+v", audit.events)
		}
	}
}

type failingListStore struct {
	*infrastructure.InMemoryStore
}

func (failingListStore) ListBySession(context.Context, string, int, int) ([]domain.CommandEntry, int, error) {
	return nil, 0, errors.New("database: connection reset")
}

// A page the store could not read is not served, so it is not on the record either, and
// is neither a refusal nor a missing dependency.
func TestGetRecording_APageTheStoreCouldNotReadIsNotOnTheRecord(t *testing.T) {
	audit := &fakeAudit{}
	svc := NewRecorderService(failingListStore{infrastructure.NewInMemoryStore()}, &fakeAuthz{}, audit)
	_, _, err := svc.GetRecording(context.Background(), reader, auditor, "s1", 1, 20)
	if err == nil || errors.Is(err, domain.ErrForbidden) || errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("a store failure: %v", err)
	}
	if len(audit.events) != 0 {
		t.Fatalf("a page that was not read is on the record: %+v", audit.events)
	}
}

// -- a refused read is on the record, within a budget per identity (ADR-0024) -------

type testClock struct{ t time.Time }

func (c *testClock) Now() time.Time          { return c.t }
func (c *testClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func refusals(a *fakeAudit, actor string) int {
	n := 0
	for _, e := range a.events {
		if e.action == "recording.read" && !e.success && e.actor == actor {
			n++
		}
	}
	return n
}

func TestGetRecording_ARefusalIsAnEventUnderTheCallersName(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	_, _ = svc.Record(context.Background(), []domain.CommandEntry{entry("s1", "x", time.Now())})
	if _, _, err := svc.GetRecording(context.Background(), "u_bob", []string{"dba"}, "s1", 1, 20); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("want forbidden, got %v", err)
	}
	want := auditEvent{actor: "u_bob", action: "recording.read", resourceType: "session", resourceID: "s1", success: false}
	if len(audit.events) != 1 || audit.events[0] != want {
		t.Fatalf("events %+v, want %+v", audit.events, want)
	}
}

func TestGetRecording_RefusalsAreWrittenWithinTheIdentitysBudget(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	clock := &testClock{t: time.Date(2026, 10, 30, 9, 0, 0, 0, time.UTC)}
	svc.WithClock(clock.Now)
	ctx := context.Background()

	var first error
	for i := 0; i < 25; i++ {
		_, _, err := svc.GetRecording(ctx, "u_mallory", []string{"dba"}, "s"+string(rune('a'+i%5)), 1, 20)
		if !errors.Is(err, domain.ErrForbidden) {
			t.Fatalf("refusal %d: %v", i, err)
		}
		if first == nil {
			first = err
		}
	}
	if n := refusals(audit, "u_mallory"); n != DefaultReadAuditBurst {
		t.Fatalf("%d of 25 refusals written, want the burst of %d", n, DefaultReadAuditBurst)
	}
	// Another identity's budget is its own.
	_, _, _ = svc.GetRecording(ctx, "u_bob", []string{"dba"}, "sa", 1, 20)
	if n := refusals(audit, "u_bob"); n != 1 {
		t.Fatalf("%d refusal(s) of Bob's written, want 1", n)
	}
	// 6 a minute: one more ten seconds later.
	clock.advance(10 * time.Second)
	_, _, _ = svc.GetRecording(ctx, "u_mallory", []string{"dba"}, "sa", 1, 20)
	if n := refusals(audit, "u_mallory"); n != DefaultReadAuditBurst+1 {
		t.Fatalf("%d written 10 s later, want %d", n, DefaultReadAuditBurst+1)
	}
}

// The answer never depends on the budget, nor on the audit: the same refusal, written,
// suppressed or lost.
func TestGetRecording_ARefusalIsTheSameWhateverTheBudgetOrTheAuditSays(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	svc.WithReadRefusalAudit(1, 1)
	ctx := context.Background()
	_, _, written := svc.GetRecording(ctx, "u_bob", []string{"dba"}, "s1", 1, 20)
	_, _, suppressed := svc.GetRecording(ctx, "u_bob", []string{"dba"}, "s1", 1, 20)
	audit.err = errors.New("audit down")
	_, _, lost := svc.GetRecording(ctx, "u_alice", []string{"dba"}, "s1", 1, 20)
	if written == nil || written.Error() != suppressed.Error() || written.Error() != lost.Error() || !errors.Is(lost, domain.ErrForbidden) {
		t.Fatalf("refusals differ: %v / %v / %v", written, suppressed, lost)
	}
}

func TestGetRecording_ASpentBudgetIsOneLogLinePerEpisode_AndALostRefusalIsLogged(t *testing.T) {
	var logs strings.Builder
	log.SetOutput(&logs)
	defer log.SetOutput(os.Stderr)

	svc, _, _, audit := newAuditedService()
	svc.WithReadRefusalAudit(2, 1)
	for i := 0; i < 6; i++ {
		_, _, _ = svc.GetRecording(context.Background(), "u_mallory", []string{"dba"}, "s1", 1, 20)
	}
	if n := strings.Count(logs.String(), "are no longer written to the audit one by one"); n != 1 {
		t.Fatalf("%d log line(s) for one episode, want 1:\n%s", n, logs.String())
	}
	audit.err = errors.New("dial tcp 10.0.0.9:8082: connection refused")
	_, _, _ = svc.GetRecording(context.Background(), "u_bob", []string{"dba"}, "s1", 1, 20)
	if !strings.Contains(logs.String(), "could not be audited") || !strings.Contains(logs.String(), "10.0.0.9:8082") {
		t.Fatalf("a refusal that could not be written is not in the log:\n%s", logs.String())
	}
}

// Served reads are not refusals: they spend nothing of the budget (ADR-0022 still holds).
func TestGetRecording_ServedReadsSpendNothingOfTheRefusalBudget(t *testing.T) {
	svc, _, _, audit := newAuditedService()
	for i := 0; i < 3*DefaultReadAuditBurst; i++ {
		if _, _, err := svc.GetRecording(context.Background(), "u_carol", auditor, "s1", 1, 20); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < DefaultReadAuditBurst; i++ {
		_, _, _ = svc.GetRecording(context.Background(), "u_carol", []string{"dba"}, "s1", 1, 20)
	}
	if n := refusals(audit, "u_carol"); n != DefaultReadAuditBurst {
		t.Fatalf("%d refusal(s) written, want the full burst: served reads must not have spent it", n)
	}
}

// What did not reach a refusal of policy writes no refusal: no name, an Authorization
// Service that does not answer, an id that cannot be a session.
func TestGetRecording_OnlyARefusalOfPolicyIsARefusalOnTheRecord(t *testing.T) {
	svc, _, authz, audit := newAuditedService()
	ctx := context.Background()
	_, _, _ = svc.GetRecording(ctx, "", []string{"dba"}, "s1", 1, 20)
	authz.err = errors.New("connection refused")
	_, _, _ = svc.GetRecording(ctx, "u_bob", []string{"dba"}, "s1", 1, 20)
	authz.err = nil
	asked := len(authz.resources)
	for _, bad := range []string{"", strings.Repeat("x", maxSessionIDBytes+1), "s\xff1", "s\n1", "s\x1b1"} {
		for _, roles := range [][]string{{"dba"}, auditor} {
			if _, _, err := svc.GetRecording(ctx, "u_bob", roles, bad, 1, 20); !errors.Is(err, domain.ErrNotASessionID) {
				t.Fatalf("%q: want ErrNotASessionID, got %v", bad, err)
			}
		}
	}
	if len(authz.resources) != asked {
		t.Fatalf("an id that cannot be a session reached the Authorization Service")
	}
	if len(audit.events) != 0 {
		t.Fatalf("events %+v, want none", audit.events)
	}
	// The longest id that can be a session is still read.
	if _, _, err := svc.GetRecording(ctx, "u_carol", auditor, strings.Repeat("x", maxSessionIDBytes), 1, 20); err != nil {
		t.Fatalf("a %d-byte id: %v", maxSessionIDBytes, err)
	}
}

package application

import (
	"context"
	"errors"
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

func newService() (*RecorderService, *infrastructure.InMemoryStore, *fakeAuthz) {
	store := infrastructure.NewInMemoryStore()
	authz := &fakeAuthz{}
	return NewRecorderService(store, authz), store, authz
}

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

	got, total, err := svc.GetRecording(ctx, auditor, "s1", 1, 20)
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
			got, total, _ := svc.GetRecording(context.Background(), auditor, "s1", 1, 20)
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
	got, _, _ := svc.GetRecording(ctx, auditor, "s1", 1, 20)
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
	got, _, _ := svc.GetRecording(ctx, auditor, "s1", 1, 20)
	if want := []string{"first-a", "first-b", "third"}; !equal(commandsOf(got), want) {
		t.Fatalf("expected %q, got %q", want, commandsOf(got))
	}
}

func TestGetRecording_OnlyReturnsTheRequestedSession(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	now := time.Now().UTC()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("s1", "mine", now), entry("s2", "theirs", now)})

	got, total, _ := svc.GetRecording(ctx, auditor, "s1", 1, 20)
	if total != 1 || !equal(commandsOf(got), []string{"mine"}) {
		t.Fatalf("expected only s1's entry, got %q (total %d)", commandsOf(got), total)
	}
}

func TestGetRecording_AnEmptySessionIsAnEmptyPageNotAnError(t *testing.T) {
	svc, _, _ := newService()
	got, total, err := svc.GetRecording(context.Background(), auditor, "no-such-session", 1, 20)
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

	page2, total, _ := svc.GetRecording(ctx, auditor, "s1", 2, 10)
	if total != 25 || len(page2) != 10 || page2[0].Command != "cmd-k" {
		t.Fatalf("page 2 of size 10: total=%d len=%d first=%q", total, len(page2), page2[0].Command)
	}
	last, _, _ := svc.GetRecording(ctx, auditor, "s1", 3, 10)
	if len(last) != 5 {
		t.Fatalf("expected the last page to hold 5, got %d", len(last))
	}
	beyond, total, _ := svc.GetRecording(ctx, auditor, "s1", 9, 10)
	if len(beyond) != 0 || total != 25 {
		t.Fatalf("a page past the end must be empty with the real total, got %d entries total=%d", len(beyond), total)
	}

	// Clamping: page < 1 → 1; pageSize < 1 → 20; pageSize > 100 → 100.
	first, _, _ := svc.GetRecording(ctx, auditor, "s1", 0, 0)
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
		got, total, err := svc.GetRecording(ctx, roles, "s1", 1, 20)
		if !errors.Is(err, domain.ErrForbidden) || got != nil || total != 0 {
			t.Fatalf("roles %v: expected ErrForbidden and no data, got %v total=%d err=%v", roles, got, total, err)
		}
	}
	if authz.resources[0] != "recording:session:s1" || authz.actions[0] != "recording:session:read" {
		t.Fatalf("RBAC was asked about %q / %q", authz.resources[0], authz.actions[0])
	}
}

func TestGetRecording_FailsClosedWhenAuthorizationIsUnreachable(t *testing.T) {
	svc, _, authz := newService()
	_, _ = svc.Record(context.Background(), []domain.CommandEntry{entry("s1", "x", time.Now())})
	authz.err = errors.New("connection refused")

	_, _, err := svc.GetRecording(context.Background(), auditor, "s1", 1, 20)
	if !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("an unreachable Authorization Service must deny, got %v", err)
	}
}

// 403 must not depend on whether the session exists, or the denial itself
// would let an unauthorized caller probe for session ids.
func TestGetRecording_DenialDoesNotRevealWhetherASessionHasEntries(t *testing.T) {
	svc, _, _ := newService()
	ctx := context.Background()
	_, _ = svc.Record(ctx, []domain.CommandEntry{entry("exists", "x", time.Now())})

	_, _, errExisting := svc.GetRecording(ctx, []string{"dba"}, "exists", 1, 20)
	_, _, errMissing := svc.GetRecording(ctx, []string{"dba"}, "does-not-exist", 1, 20)
	if !errors.Is(errExisting, domain.ErrForbidden) || !errors.Is(errMissing, domain.ErrForbidden) {
		t.Fatalf("both must be forbidden, got %v / %v", errExisting, errMissing)
	}
}

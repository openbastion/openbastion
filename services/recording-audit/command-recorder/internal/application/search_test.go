package application

// ADR-0080: the search decrypts on the fly, in a bounded window. Each session is authorized
// before anything of it is decrypted; the search is written to the audit before anything is
// decrypted, with a digest of the text, never the text; each session the answer discloses is a
// recording.read written before the answer; any of it unwritten, nothing is served.

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/infrastructure"
)

var searchKey = []byte(strings.Repeat("k", SearchKeyBytes))

// sessionAuthz allows the sessions it holds, and counts what it was asked.
type sessionAuthz struct {
	allow map[string]bool
	err   error
	asked int
}

func (a *sessionAuthz) CheckAccess(_ context.Context, _ []string, resource, _ string) (bool, string, error) {
	a.asked++
	if a.err != nil {
		return false, "", a.err
	}
	return a.allow[strings.TrimPrefix(resource, "recording:session:")], "", nil
}

type detailedEvent struct {
	actor, action, resourceType, resourceID string
	details                                 map[string]string
}

// searchAudit writes details; failAt fails the nth event (1-based), 0 never; onWrite runs as
// each event is written.
type searchAudit struct {
	events  []detailedEvent
	failAt  int
	onWrite func(action string)
}

func (a *searchAudit) EmitEvent(ctx context.Context, actor, action, rt, rid string, ok bool) error {
	return a.EmitEventWithDetails(ctx, actor, action, rt, rid, nil, ok)
}

func (a *searchAudit) EmitEventWithDetails(_ context.Context, actor, action, rt, rid string, details map[string]string, _ bool) error {
	if a.failAt == len(a.events)+1 {
		return errors.New("audit-service: connection refused")
	}
	if a.onWrite != nil {
		a.onWrite(action)
	}
	a.events = append(a.events, detailedEvent{actor, action, rt, rid, details})
	return nil
}

type searchWorld struct {
	svc   *RecorderService
	store *infrastructure.InMemoryStore
	authz *sessionAuthz
	audit *searchAudit
	now   time.Time
}

func newSearchWorld(t *testing.T) *searchWorld {
	t.Helper()
	w := &searchWorld{store: infrastructure.NewInMemoryStore(), authz: &sessionAuthz{allow: map[string]bool{}}, audit: &searchAudit{},
		now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	w.svc = NewRecorderService(w.store, w.authz, w.audit).WithSearchKey(searchKey)
	return w
}

// record makes a session started at, with these commands, and allows it if allowed.
func (w *searchWorld) record(t *testing.T, id string, at time.Time, allowed bool, commands ...string) {
	t.Helper()
	var entries []domain.CommandEntry
	for i, c := range commands {
		entries = append(entries, domain.CommandEntry{SessionID: id, Timestamp: at.Add(time.Duration(i) * time.Second), Command: c})
	}
	if _, err := w.svc.Record(context.Background(), entries); err != nil {
		t.Fatal(err)
	}
	w.store.SetStarted(id, at)
	w.authz.allow[id] = allowed
}

func (w *searchWorld) search(q string) (SearchResult, error) {
	return w.svc.Search(context.Background(), "u_carol", []string{"auditor"}, q, w.now.Add(-24*time.Hour), w.now)
}

func TestSearch_ASubstringIsFoundWithoutCase_InTheSessionsTheCallerMayRead(t *testing.T) {
	w := newSearchWorld(t)
	w.record(t, "s-mine", w.now.Add(-time.Hour), true, "ls -la", "sudo CAT /etc/Shadow", "exit")
	w.record(t, "s-other", w.now.Add(-2*time.Hour), false, "cat /etc/shadow")
	w.record(t, "s-quiet", w.now.Add(-3*time.Hour), true, "uptime")
	res, err := w.search("cat /ETC/shadow")
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Sessions) != 1 || res.Sessions[0].SessionID != "s-mine" || len(res.Sessions[0].Hits) != 1 || res.Sessions[0].Hits[0].Command != "sudo CAT /etc/Shadow" {
		t.Fatalf("result %+v, want the one command of s-mine", res)
	}
	if w.store.Opened("s-other") != 0 {
		t.Fatal("a session the caller may not read was decrypted")
	}
	if w.store.Opened("s-quiet") != 1 {
		t.Fatal("an allowed session was not looked into")
	}
	// Accents are compared once normalized: é composed or decomposed is the same character.
	w.record(t, "s-accent", w.now.Add(-4*time.Hour), true, "echo café")
	if res, _ := w.search("café"); len(res.Sessions) != 1 || res.Sessions[0].SessionID != "s-accent" {
		t.Fatalf("NFC: %+v", res)
	}
}

func TestSearch_IsWrittenBeforeAnythingIsDecrypted_WithADigestOfTheText_NeverTheText(t *testing.T) {
	w := newSearchWorld(t)
	w.record(t, "s1", w.now.Add(-time.Hour), true, "mysql -p'Sup3rSecret!'")
	w.record(t, "s2", w.now.Add(-2*time.Hour), false, "whoami")
	openedAtSearch := -1
	w.audit.onWrite = func(action string) {
		if action == AuditActionSearch {
			openedAtSearch = w.store.Opened("s1")
		}
	}
	res, err := w.search("Sup3rSecret")
	if err != nil {
		t.Fatal(err)
	}
	if openedAtSearch != 0 {
		t.Fatalf("s1 was decrypted %d time(s) before the search was written", openedAtSearch)
	}
	ev := w.audit.events[0]
	mac := hmac.New(sha256.New, searchKey)
	mac.Write([]byte(fold("Sup3rSecret")))
	want := map[string]string{"candidates": "2", "allowed": "1", "refused": "1", "truncated": "false", "q_hmac": hex.EncodeToString(mac.Sum(nil))}
	if ev.action != AuditActionSearch || ev.actor != "u_carol" || ev.resourceType != "recording_search" || ev.resourceID != res.SearchID {
		t.Fatalf("search event %+v", ev)
	}
	for k, v := range want {
		if ev.details[k] != v {
			t.Fatalf("details[%s] = %q, want %q (%v)", k, ev.details[k], v, ev.details)
		}
	}
	for _, e := range w.audit.events {
		for _, v := range e.details {
			if strings.Contains(strings.ToLower(v), "sup3rsecret") {
				t.Fatalf("the text searched is in the audit: %+v", e)
			}
		}
	}
	// Then the session the answer discloses: a recording.read, tied to the search.
	if len(w.audit.events) != 2 || w.audit.events[1].action != AuditActionRead || w.audit.events[1].resourceID != "s1" || w.audit.events[1].details["search_id"] != res.SearchID {
		t.Fatalf("events %+v, want the search then one read of s1", w.audit.events)
	}
}

func TestSearch_TheAuditDown_NothingIsDecrypted_AReadUnwritten_NothingIsServed(t *testing.T) {
	w := newSearchWorld(t)
	w.record(t, "s1", w.now.Add(-time.Hour), true, "rm -rf /tmp/x")
	w.record(t, "s2", w.now.Add(-2*time.Hour), true, "rm -rf /tmp/y")
	w.audit.failAt = 1
	if _, err := w.search("rm -rf"); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("the search unwritten: %v, want ErrUnavailable", err)
	}
	if w.store.Opened("s1")+w.store.Opened("s2") != 0 {
		t.Fatal("sessions were decrypted although the search could not be written")
	}
	w.audit.failAt = 3 // the search, the read of one session, then the second read fails
	res, err := w.search("rm -rf")
	if !errors.Is(err, domain.ErrUnavailable) || len(res.Sessions) != 0 {
		t.Fatalf("a read unwritten: %+v %v, want nothing served and ErrUnavailable", res, err)
	}
}

func TestSearch_TheAuthorizationServiceDown_NothingIsDecrypted(t *testing.T) {
	w := newSearchWorld(t)
	w.record(t, "s1", w.now.Add(-time.Hour), true, "id")
	w.authz.err = errors.New("authorization: connection refused")
	if _, err := w.search("id -u"); !errors.Is(err, domain.ErrUnavailable) || w.store.Opened("s1") != 0 || len(w.audit.events) != 0 {
		t.Fatalf("%v, opened %d, %d event(s): want ErrUnavailable, nothing decrypted, nothing written", err, w.store.Opened("s1"), len(w.audit.events))
	}
}

func TestSearch_TheBounds(t *testing.T) {
	w := newSearchWorld(t)
	ctx := context.Background()
	for name, tc := range map[string]struct {
		q        string
		from, to time.Time
	}{
		"two characters":      {"ab", w.now.Add(-time.Hour), w.now},
		"257 characters":      {strings.Repeat("a", 257), w.now.Add(-time.Hour), w.now},
		"a window of 32 days": {"abc", w.now.Add(-32 * 24 * time.Hour), w.now},
		"from after to":       {"abc", w.now, w.now.Add(-time.Hour)},
		"no window":           {"abc", time.Time{}, time.Time{}},
	} {
		if _, err := w.svc.Search(ctx, "u_carol", nil, tc.q, tc.from, tc.to); !errors.Is(err, ErrInvalidSearch) {
			t.Fatalf("%s: %v, want ErrInvalidSearch", name, err)
		}
	}
	if len(w.audit.events) != 0 || w.authz.asked != 0 {
		t.Fatal("a search out of bounds asked or wrote something")
	}
	if _, err := w.svc.Search(ctx, "", nil, "abc", w.now.Add(-time.Hour), w.now); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v", err)
	}
	if _, err := NewRecorderService(w.store, w.authz, w.audit).Search(ctx, "u_carol", nil, "abc", w.now.Add(-time.Hour), w.now); !errors.Is(err, ErrSearchDisabled) {
		t.Fatalf("no key: %v, want ErrSearchDisabled", err)
	}
	// 31 days exactly is allowed.
	if _, err := w.svc.Search(ctx, "u_carol", nil, "abc", w.now.Add(-SearchMaxWindow), w.now); err != nil {
		t.Fatalf("31 days: %v", err)
	}
}

func TestSearch_MoreThan200Sessions_IsTruncated_AndTheRestIsNotDecrypted(t *testing.T) {
	w := newSearchWorld(t)
	for i := 0; i < SearchMaxSessions+5; i++ {
		w.record(t, fmt.Sprintf("s%03d", i), w.now.Add(-time.Duration(i+1)*time.Minute), true, "needle here")
	}
	res, err := w.search("needle")
	if err != nil {
		t.Fatal(err)
	}
	if !res.Truncated || len(res.Sessions) != SearchMaxSessions || w.authz.asked != SearchMaxSessions {
		t.Fatalf("truncated=%v, %d sessions, %d asked; want true, %d, %d", res.Truncated, len(res.Sessions), w.authz.asked, SearchMaxSessions, SearchMaxSessions)
	}
	// The most recent first: the oldest five are the ones left out, and never decrypted.
	for i := SearchMaxSessions; i < SearchMaxSessions+5; i++ {
		if n := w.store.Opened(fmt.Sprintf("s%03d", i)); n != 0 {
			t.Fatalf("s%03d, past the bound, was decrypted", i)
		}
	}
}

func TestSearch_AtMost50HitsASession_And1000AnAnswer(t *testing.T) {
	w := newSearchWorld(t)
	many := make([]string, 80)
	for i := range many {
		many[i] = fmt.Sprintf("echo needle %d", i)
	}
	for i := 0; i < 25; i++ {
		w.record(t, fmt.Sprintf("s%02d", i), w.now.Add(-time.Duration(i+1)*time.Minute), true, many...)
	}
	res, err := w.search("needle")
	if err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, s := range res.Sessions {
		if len(s.Hits) > SearchMaxPerSession {
			t.Fatalf("%s: %d hits", s.SessionID, len(s.Hits))
		}
		total += len(s.Hits)
	}
	if total != SearchMaxHits || !res.Truncated {
		t.Fatalf("%d hits, truncated=%v; want %d and true", total, res.Truncated, SearchMaxHits)
	}
}

package application_test

// ADR-0080, point 5: the search of sessions, on their metadata. A session is served to who may
// read it — its requester and the person who decided it, who write nothing; anybody else on the
// strength of a policy on its account, and each such session is a session.read written before it
// is served. One unwritten: nothing is served. The text is a substring without wildcards.

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

// accountAuthz allows session:read on the accounts it holds, and counts what it was asked.
type accountAuthz struct {
	mu    sync.Mutex
	allow map[string]bool
	err   error
	asked int
}

func (a *accountAuthz) CheckAccess(_ context.Context, _ []string, resource, _ string) (bool, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked++
	if a.err != nil {
		return false, "", a.err
	}
	return a.allow[strings.TrimPrefix(resource, application.SessionReadResourcePrefix)], "", nil
}

// readAudit remembers the reads written; failAt fails the nth event (1-based).
type readAudit struct {
	mu     sync.Mutex
	reads  []string
	failAt int
	n      int
}

func (a *readAudit) EmitEvent(_ context.Context, actor, action, _, id string, ok bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.n++
	if a.n == a.failAt {
		return errors.New("audit-service: connection refused")
	}
	if action == "session.read" && ok {
		a.reads = append(a.reads, actor+":"+id)
	}
	return nil
}

func (a *readAudit) EmitEventWithDetails(ctx context.Context, actor, action, rt, id string, _ map[string]string, ok bool) error {
	return a.EmitEvent(ctx, actor, action, rt, id, ok)
}

type searchFixture struct {
	broker *application.SessionBrokerService
	store  *infrastructure.InMemoryStore
	authz  *accountAuthz
	audit  *readAudit
	now    time.Time
}

func newSearchFixture() *searchFixture {
	f := &searchFixture{store: infrastructure.NewInMemoryStore(), authz: &accountAuthz{allow: map[string]bool{}}, audit: &readAudit{},
		now: time.Date(2026, 11, 7, 12, 0, 0, 0, time.UTC)}
	f.broker = application.NewSessionBrokerService(f.store, f.authz, &fakeVaultAuthorizer{}, f.audit, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithClock(func() time.Time { return f.now })
	return f
}

func (f *searchFixture) save(t *testing.T, s domain.Session) {
	t.Helper()
	if s.Status == "" {
		s.Status = domain.StatusTerminated
	}
	if s.ExpiresAt.IsZero() {
		s.ExpiresAt = s.CreatedAt.Add(30 * time.Minute)
	}
	if err := f.store.Save(context.Background(), &s); err != nil {
		t.Fatal(err)
	}
}

func (f *searchFixture) search(caller, text string, mod ...func(*application.SessionSearchRequest)) (application.SessionSearchResult, error) {
	req := application.SessionSearchRequest{SessionSearch: domain.SessionSearch{Text: text, From: f.now.Add(-24 * time.Hour), To: f.now}}
	for _, m := range mod {
		m(&req)
	}
	return f.broker.SearchSessions(context.Background(), caller, []string{"auditor"}, req)
}

func foundIDs(r application.SessionSearchResult) []string {
	var out []string
	for _, s := range r.Sessions {
		out = append(out, s.ID)
	}
	return out
}

func TestSessionSearch_ThePolicyHolderFindsTheSessionsOfItsAccounts_EachARecordedRead(t *testing.T) {
	f := newSearchFixture()
	f.authz.allow["acct-db"] = true
	f.save(t, domain.Session{ID: "s1", RequestedBy: "u_alice", PrivilegedAccountID: "acct-db", Justification: "Incident INC-4242 on prod", CreatedAt: f.now.Add(-time.Hour)})
	f.save(t, domain.Session{ID: "s2", RequestedBy: "u_bob", PrivilegedAccountID: "acct-web", Justification: "incident inc-4242 too", CreatedAt: f.now.Add(-2 * time.Hour)})
	f.save(t, domain.Session{ID: "s3", RequestedBy: "u_bob", PrivilegedAccountID: "acct-db", Ticket: "INC-4242", CreatedAt: f.now.Add(-3 * time.Hour)})
	f.save(t, domain.Session{ID: "s4", RequestedBy: "u_bob", PrivilegedAccountID: "acct-db", Justification: "patching", CreatedAt: f.now.Add(-4 * time.Hour)})
	r, err := f.search("u_carol", "inc-4242")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(foundIDs(r)) != "[s1 s3]" || r.Next != nil {
		t.Fatalf("found %v next=%v, want [s1 s3] (most recent first), nothing of acct-web", foundIDs(r), r.Next)
	}
	if fmt.Sprint(f.audit.reads) != "[u_carol:s1 u_carol:s3]" {
		t.Fatalf("reads written %v, want one per session served", f.audit.reads)
	}
	if f.authz.asked != 2 {
		t.Fatalf("the Authorization Service was asked %d times, want once per account", f.authz.asked)
	}
}

func TestSessionSearch_TheRequesterAndTheDeciderSeeTheirsWithoutAPolicy_AndWriteNothing(t *testing.T) {
	f := newSearchFixture()
	f.save(t, domain.Session{ID: "mine", RequestedBy: "u_alice", PrivilegedAccountID: "acct-db", Justification: "deploy v2", CreatedAt: f.now.Add(-time.Hour)})
	f.save(t, domain.Session{ID: "decided", RequestedBy: "u_bob", DecidedBy: "u_alice", PrivilegedAccountID: "acct-db", Justification: "deploy v2", BreakGlass: true, CreatedAt: f.now.Add(-2 * time.Hour)})
	f.save(t, domain.Session{ID: "other", RequestedBy: "u_bob", PrivilegedAccountID: "acct-db", Justification: "deploy v2", CreatedAt: f.now.Add(-3 * time.Hour)})
	r, err := f.search("u_alice", "deploy")
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(foundIDs(r)) != "[mine decided]" || len(f.audit.reads) != 0 {
		t.Fatalf("found %v, reads %v; want [mine decided] and nothing written", foundIDs(r), f.audit.reads)
	}
}

func TestSessionSearch_OneReadUnwritten_NothingIsServed_TheAuthorizationDown_Neither(t *testing.T) {
	f := newSearchFixture()
	f.authz.allow["acct-db"] = true
	f.save(t, domain.Session{ID: "s1", RequestedBy: "u_bob", PrivilegedAccountID: "acct-db", Justification: "x-ray", CreatedAt: f.now.Add(-time.Hour)})
	f.save(t, domain.Session{ID: "s2", RequestedBy: "u_bob", PrivilegedAccountID: "acct-db", Justification: "x-ray", CreatedAt: f.now.Add(-2 * time.Hour)})
	f.audit.failAt = 2
	if r, err := f.search("u_carol", "x-ray"); !errors.Is(err, domain.ErrUnavailable) || len(r.Sessions) != 0 {
		t.Fatalf("a read unwritten: %v %v, want ErrUnavailable and nothing", foundIDs(r), err)
	}
	f.audit.failAt = 0
	f.authz.err = errors.New("authorization: connection refused")
	if r, err := f.search("u_carol", "x-ray"); !errors.Is(err, domain.ErrUnavailable) || len(r.Sessions) != 0 {
		t.Fatalf("the Authorization Service down: %v %v", foundIDs(r), err)
	}
}

func TestSessionSearch_TheTextHasNoWildcards_AndTheFiltersHold(t *testing.T) {
	f := newSearchFixture()
	f.authz.allow["acct"] = true
	f.save(t, domain.Session{ID: "pct", RequestedBy: "u_x", PrivilegedAccountID: "acct", Justification: "disk at 100% on db1", Protocol: "ssh", CreatedAt: f.now.Add(-time.Hour)})
	f.save(t, domain.Session{ID: "plain", RequestedBy: "u_x", PrivilegedAccountID: "acct", Justification: "disk at 1000 on db1", Protocol: "vnc", BreakGlass: true, CreatedAt: f.now.Add(-2 * time.Hour)})
	if r, _ := f.search("u_carol", "100%"); fmt.Sprint(foundIDs(r)) != "[pct]" {
		t.Fatalf("100%%: %v, want [pct] only — %% is not a wildcard", foundIDs(r))
	}
	if r, _ := f.search("u_carol", "db_"); len(r.Sessions) != 0 {
		t.Fatalf("db_: %v, want nothing — _ is not a wildcard", foundIDs(r))
	}
	if r, _ := f.search("u_carol", "", func(q *application.SessionSearchRequest) { q.Protocol = "vnc" }); fmt.Sprint(foundIDs(r)) != "[plain]" {
		t.Fatalf("protocol vnc: %v", foundIDs(r))
	}
	bg := true
	if r, _ := f.search("u_carol", "", func(q *application.SessionSearchRequest) { q.BreakGlass = &bg }); fmt.Sprint(foundIDs(r)) != "[plain]" {
		t.Fatalf("break-glass: %v", foundIDs(r))
	}
	if r, _ := f.search("u_carol", "", func(q *application.SessionSearchRequest) { q.Status = domain.StatusActive }); len(r.Sessions) != 0 {
		t.Fatalf("status active: %v, want nothing (both terminated)", foundIDs(r))
	}
}

func TestSessionSearch_TheBounds(t *testing.T) {
	f := newSearchFixture()
	for name, mod := range map[string]func(*application.SessionSearchRequest){
		"two characters":      func(q *application.SessionSearchRequest) { q.Text = "ab" },
		"257 characters":      func(q *application.SessionSearchRequest) { q.Text = strings.Repeat("a", 257) },
		"a window of 32 days": func(q *application.SessionSearchRequest) { q.From = f.now.Add(-32 * 24 * time.Hour) },
		"from after to":       func(q *application.SessionSearchRequest) { q.From, q.To = f.now, f.now.Add(-time.Hour) },
		"no window":           func(q *application.SessionSearchRequest) { q.From, q.To = time.Time{}, time.Time{} },
	} {
		if _, err := f.search("u_carol", "abc", mod); !errors.Is(err, application.ErrInvalidSearch) {
			t.Fatalf("%s: %v, want ErrInvalidSearch", name, err)
		}
	}
	if _, err := f.search("", "abc"); !errors.Is(err, domain.ErrForbidden) {
		t.Fatalf("no caller: %v", err)
	}
	if f.authz.asked != 0 || f.audit.n != 0 {
		t.Fatal("a search out of bounds asked or wrote something")
	}
}

func TestSessionSearch_PagesOf50_TheNextPageStartsWhereThisOneStopped(t *testing.T) {
	f := newSearchFixture()
	f.authz.allow["acct"] = true
	for i := 0; i < 120; i++ {
		f.save(t, domain.Session{ID: fmt.Sprintf("s%03d", i), RequestedBy: "u_x", PrivilegedAccountID: "acct", Justification: "batch", CreatedAt: f.now.Add(-time.Duration(i+1) * time.Minute)})
	}
	seen := map[string]bool{}
	var cursor *domain.SearchCursor
	pages := 0
	for {
		c := cursor
		r, err := f.search("u_carol", "batch", func(q *application.SessionSearchRequest) { q.After = c })
		if err != nil {
			t.Fatal(err)
		}
		pages++
		if len(r.Sessions) > application.SessionSearchPageSize {
			t.Fatalf("page %d: %d sessions", pages, len(r.Sessions))
		}
		for _, s := range r.Sessions {
			if seen[s.ID] {
				t.Fatalf("%s served twice", s.ID)
			}
			seen[s.ID] = true
		}
		if r.Next == nil {
			break
		}
		cursor = r.Next
	}
	if len(seen) != 120 || pages != 3 {
		t.Fatalf("%d sessions in %d pages, want 120 in 3", len(seen), pages)
	}
}

// Past 500 sessions looked at, a page ends even with fewer than 50 served, and says where the
// next one starts: a search of an account the caller may not read costs bounded work.
func TestSessionSearch_APageLooksAtMost500Sessions(t *testing.T) {
	f := newSearchFixture()
	f.authz.allow["mine"] = true
	for i := 0; i < 600; i++ {
		f.save(t, domain.Session{ID: fmt.Sprintf("o%03d", i), RequestedBy: "u_x", PrivilegedAccountID: "other", Justification: "noise", CreatedAt: f.now.Add(-time.Duration(i+1) * time.Second)})
	}
	f.save(t, domain.Session{ID: "late", RequestedBy: "u_x", PrivilegedAccountID: "mine", Justification: "noise", CreatedAt: f.now.Add(-time.Hour)})
	r, err := f.search("u_carol", "noise")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Sessions) != 0 || r.Next == nil {
		t.Fatalf("first page: %v next=%v, want nothing yet and a next page", foundIDs(r), r.Next)
	}
	r, _ = f.search("u_carol", "noise", func(q *application.SessionSearchRequest) { q.After = r.Next })
	if fmt.Sprint(foundIDs(r)) != "[late]" {
		t.Fatalf("second page: %v, want [late]", foundIDs(r))
	}
}

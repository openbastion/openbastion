package application_test

// Break-glass (ADR-0009) at the Session Broker: who may ask, under what
// conditions, what is audited, and what the proxy is told.

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

// resourceAuthz allows exactly the (resource) strings it is given, and notes what
// it was asked — so a test can see that break-glass is judged on ITS resource,
// not on the one that governs ordinary sessions.
type resourceAuthz struct {
	mu         sync.Mutex
	allow      map[string]bool
	asked      []string
	askedRoles [][]string
	failOn     string // a resource whose check errors out
	allowAny   bool   // every resource is allowed: for tests about what is NOT the policy's doing
}

func (a *resourceAuthz) CheckAccess(ctx context.Context, roles []string, resource, action string) (bool, string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, resource)
	a.askedRoles = append(a.askedRoles, append([]string(nil), roles...))
	if resource == a.failOn {
		return false, "", errors.New("authorization service unreachable")
	}
	if a.allowAny || a.allow[resource] {
		return true, "allow policy matched", nil
	}
	return false, "no policy matches this resource for the caller's roles", nil
}

type auditRecord struct {
	action   string
	success  bool
	actor    string
	resource string
}

type journalAudit struct {
	mu     sync.Mutex
	events []auditRecord
	failOn string
}

func (a *journalAudit) EmitEvent(ctx context.Context, actorID, action, resourceType, resourceID string, success bool) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if action == a.failOn {
		return errors.New("audit unreachable")
	}
	a.events = append(a.events, auditRecord{action, success, actorID, resourceID})
	return nil
}

// stopFailing lets the audit write again, to show that what a failure refused stays
// refused only for as long as it fails.
func (a *journalAudit) stopFailing() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.failOn = ""
}

func (a *journalAudit) has(action string, success bool) bool {
	for _, e := range a.events {
		if e.action == action && e.success == success {
			return true
		}
	}
	return false
}

func (a *journalAudit) count(action string) int {
	n := 0
	for _, e := range a.events {
		if e.action == action {
			n++
		}
	}
	return n
}

const (
	acct          = "acc-prod-db"
	sessionRes    = "vault:account:" + acct
	breakGlassRes = application.BreakGlassResourcePrefix + acct
	goodReason    = "recorder down during P1 incident INC-4521"
)

// spyStore remembers every session the Broker saved, so a test can see the
// attempts that were refused as well as the ones that were granted.
type spyStore struct {
	*infrastructure.InMemoryStore
	saved []domain.Session
}

func (s *spyStore) Save(ctx context.Context, sess *domain.Session) error {
	s.saved = append(s.saved, *sess)
	return s.InMemoryStore.Save(ctx, sess)
}

type bgFixture struct {
	broker *application.SessionBrokerService
	authz  *resourceAuthz
	audit  *journalAudit
	proxy  *fakeProxyClient
	store  *spyStore
}

// newBGFixture is the Broker as it was under ADR-0009: break-glass granted at once,
// with no second person. These tests are about the six locks, which approval does not
// touch; the double validation (ADR-0011) has its own fixture and its own file.
func newBGFixture(maxMinutes int, allow ...string) *bgFixture {
	f := &bgFixture{authz: &resourceAuthz{allow: map[string]bool{}}, audit: &journalAudit{}, proxy: &fakeProxyClient{}, store: &spyStore{InMemoryStore: infrastructure.NewInMemoryStore()}}
	for _, r := range allow {
		f.authz.allow[r] = true
	}
	f.broker = application.NewSessionBrokerService(f.store, f.authz, &fakeVaultAuthorizer{}, f.audit, &fakeAccountLookup{}, f.proxy).WithBreakGlass(maxMinutes).WithoutBreakGlassApproval()
	return f
}

func (f *bgFixture) request(justification string, minutes int) (*domain.Session, error) {
	return f.broker.CreateBreakGlassSession(context.Background(), "oncall", []string{"sre"}, acct, "ssh", justification, minutes)
}

func TestBreakGlass_AGrantedRequestIsMarkedAuditedAndRemembered(t *testing.T) {
	f := newBGFixture(30, sessionRes, breakGlassRes)

	sess, err := f.request(goodReason, 20)
	if err != nil {
		t.Fatalf("CreateBreakGlassSession: %v", err)
	}
	if !sess.BreakGlass || sess.Status != domain.StatusActive {
		t.Fatalf("session = %+v", sess)
	}
	if got, _ := f.store.Get(context.Background(), sess.ID); !got.BreakGlass {
		t.Fatal("the stored session lost its break-glass mark")
	}
	if got := sess.Justification; got != goodReason {
		t.Fatalf("the justification must stay readable on the session: %q", got)
	}
	if !f.audit.has("session.breakglass_requested", true) || !f.audit.has("session.create", true) {
		t.Fatalf("both the request and the grant must be audited: %v", f.audit.events)
	}
}

// The permission is its own: being allowed to open a session on the account — or
// being a platform administrator — is not being allowed to waive recording.
func TestBreakGlass_NeedsItsOwnPolicy_SessionCreateIsNotEnough(t *testing.T) {
	f := newBGFixture(30, sessionRes) // may open a session, no break-glass policy

	sess, err := f.request(goodReason, 20)
	if err == nil {
		t.Fatalf("break-glass was granted without a break-glass policy: %+v", sess)
	}
	if !strings.Contains(err.Error(), "break-glass refused") {
		t.Fatalf("the refusal should say what was refused: %v", err)
	}
	if !f.audit.has("session.breakglass_requested", false) {
		t.Fatalf("a refused request must be audited: %v", f.audit.events)
	}
	if f.audit.has("session.create", true) {
		t.Fatalf("a refused break-glass request produced a granted session: %v", f.audit.events)
	}
	// And the question put to the Authorization Service was the break-glass one.
	if len(f.authz.asked) != 2 || f.authz.asked[1] != breakGlassRes {
		t.Fatalf("asked %v; the second question must be about %q", f.authz.asked, breakGlassRes)
	}
	// A denied attempt is still recorded (Full Auditability), as denied.
	stored := f.denied(t)
	if stored.BreakGlass != true || stored.Status != domain.StatusDenied {
		t.Fatalf("the refused attempt was not recorded as a denied break-glass session: %+v", stored)
	}
}

// denied returns the last session the Broker saved: the attempt that was refused.
func (f *bgFixture) denied(t *testing.T) domain.Session {
	t.Helper()
	if len(f.store.saved) == 0 {
		t.Fatal("no session was recorded")
	}
	return f.store.saved[len(f.store.saved)-1]
}

// The reverse: a break-glass policy without the right to open a session at all
// is not a way in either — the ordinary check still runs first.
func TestBreakGlass_StillNeedsTheOrdinarySessionPolicy(t *testing.T) {
	f := newBGFixture(30, breakGlassRes)

	if _, err := f.request(goodReason, 20); err == nil {
		t.Fatal("break-glass bypassed the ordinary session check")
	}
	if len(f.authz.asked) != 1 || f.authz.asked[0] != sessionRes {
		t.Fatalf("the ordinary check must come first and stop the request: %v", f.authz.asked)
	}
}

func TestBreakGlass_IsOffUnlessAMaximumDurationIsConfigured(t *testing.T) {
	f := newBGFixture(0, sessionRes, breakGlassRes) // the default

	_, err := f.request(goodReason, 10)
	if err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("break-glass must be refused when the platform has not enabled it, got %v", err)
	}
	if !f.audit.has("session.breakglass_requested", false) {
		t.Fatalf("the refusal must be audited: %v", f.audit.events)
	}
	for _, r := range f.authz.asked {
		if r == breakGlassRes {
			t.Fatal("the Authorization Service was asked about break-glass although it is disabled")
		}
	}
}

func TestBreakGlass_RequiresAJustification(t *testing.T) {
	for name, j := range map[string]string{
		"empty":                 "",
		"blank":                 "          ",
		"a lone mark":           ".",
		"too short":             "urgent",
		"padded to look longer": "   ok     ",
	} {
		t.Run(name, func(t *testing.T) {
			f := newBGFixture(30, sessionRes, breakGlassRes)
			if sess, err := f.request(j, 10); err == nil {
				t.Fatalf("break-glass granted with justification %q: %+v", j, sess)
			}
		})
	}
	// Characters, not bytes: a justification in French or Japanese is no shorter
	// for needing more bytes.
	f := newBGFixture(30, sessionRes, breakGlassRes)
	if _, err := f.request("panne du recorder, incident P1 en cours", 10); err != nil {
		t.Fatalf("a justification in French was refused: %v", err)
	}
	f2 := newBGFixture(30, sessionRes, breakGlassRes)
	if _, err := f2.request("録画サービス停止中の障害対応のため", 10); err != nil {
		t.Fatalf("a justification of ten wide characters was refused: %v", err)
	}
}

func TestBreakGlass_IsBoundedInTime(t *testing.T) {
	for name, tc := range map[string]struct {
		minutes int
		ok      bool
	}{
		"zero":             {0, false},
		"negative":         {-5, false},
		"the limit":        {30, true},
		"one over":         {31, false},
		"a working day":    {480, false},
		"one minute":       {1, true},
		"a plausible shot": {15, true},
	} {
		t.Run(name, func(t *testing.T) {
			f := newBGFixture(30, sessionRes, breakGlassRes)
			_, err := f.request(goodReason, tc.minutes)
			if (err == nil) != tc.ok {
				t.Fatalf("%d minutes: err = %v, want ok=%v", tc.minutes, err, tc.ok)
			}
		})
	}
}

// Fail closed, twice: an Authorization Service that cannot be asked grants
// nothing, and neither does an audit trail that cannot be written.
func TestBreakGlass_FailsClosed(t *testing.T) {
	t.Run("authorization unreachable", func(t *testing.T) {
		f := newBGFixture(30, sessionRes, breakGlassRes)
		f.authz.failOn = breakGlassRes
		if sess, err := f.request(goodReason, 10); err == nil {
			t.Fatalf("granted without being able to ask: %+v", sess)
		}
	})
	t.Run("the request cannot be audited", func(t *testing.T) {
		f := newBGFixture(30, sessionRes, breakGlassRes)
		f.audit.failOn = "session.breakglass_requested"
		sess, err := f.request(goodReason, 10)
		if err == nil {
			t.Fatalf("an emergency access that cannot be audited was granted: %+v", sess)
		}
		if f.audit.has("session.create", true) {
			t.Fatalf("a session.create(success) was emitted for a refused grant: %v", f.audit.events)
		}
	})
}

// An ordinary request never carries the mark, even from an actor who could have
// had it: break-glass is asked for, never assumed.
func TestBreakGlass_AnOrdinarySessionIsNotMarked(t *testing.T) {
	f := newBGFixture(30, sessionRes, breakGlassRes)
	sess, err := f.broker.CreateSession(context.Background(), "oncall", []string{"sre"}, acct, "ssh", "routine", 30)
	if err != nil {
		t.Fatal(err)
	}
	if sess.BreakGlass {
		t.Fatal("an ordinary session was marked break-glass")
	}
	if f.audit.count("session.breakglass_requested") != 0 {
		t.Fatalf("an ordinary session left a break-glass event: %v", f.audit.events)
	}
}

// -- what the proxy is told ------------------------------------------------------

func TestBreakGlass_TheProxyIsToldOnlyForABreakGlassSession(t *testing.T) {
	f := newBGFixture(30, sessionRes, breakGlassRes)

	bg, err := f.request(goodReason, 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), bg.ID, bg.RequestedBy); err != nil {
		t.Fatal(err)
	}
	if !f.proxy.lastBreakGlass {
		t.Fatal("the proxy was not told about a break-glass session")
	}

	plain, err := f.broker.CreateSession(context.Background(), "oncall", []string{"sre"}, acct, "ssh", "routine", 10)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := f.broker.Connect(context.Background(), plain.ID, plain.RequestedBy); err != nil {
		t.Fatal(err)
	}
	if f.proxy.lastBreakGlass {
		t.Fatal("the proxy was told to waive recording for an ordinary session")
	}
}

// Switching break-glass off takes effect at once, including for a session that
// was granted a moment earlier: the waiver is not a bearer token that outlives
// the decision to stop granting it.
func TestBreakGlass_SwitchingItOffStopsTheWaiverForSessionsAlreadyGranted(t *testing.T) {
	f := newBGFixture(30, sessionRes, breakGlassRes)
	bg, err := f.request(goodReason, 10)
	if err != nil {
		t.Fatal(err)
	}

	f.broker.WithBreakGlass(0) // the operator turns it off

	if _, _, _, err := f.broker.Connect(context.Background(), bg.ID, bg.RequestedBy); err != nil {
		t.Fatal(err)
	}
	if f.proxy.lastBreakGlass {
		t.Fatal("the waiver was still passed to the proxy after break-glass was switched off")
	}
}

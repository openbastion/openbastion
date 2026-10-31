package application_test

// Rotation after use (ADR-0037): a granted session that ends tells the Vault; a request no one
// approved was never used, and does not.

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/application"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type fakeRotator struct {
	mu    sync.Mutex
	calls []string
	ended map[string]time.Time
	down  bool // the Vault cannot be reached
}

func (f *fakeRotator) RotateAfterUse(_ context.Context, accountID, sessionID string, endedAt time.Time) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, accountID+"/"+sessionID)
	if f.ended == nil {
		f.ended = map[string]time.Time{}
	}
	f.ended[sessionID] = endedAt
	if f.down {
		return errors.New("rotate-after-use: dial tcp 10.9.8.4:8081: connection refused")
	}
	return nil
}

func (f *fakeRotator) setDown(down bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.down = down
}

func (f *fakeRotator) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *fakeRotator) seen(t *testing.T, n int) []string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		f.mu.Lock()
		got := append([]string(nil), f.calls...)
		f.mu.Unlock()
		if len(got) >= n {
			sort.Strings(got)
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestAfterUse_TheEndOfAGrantedSessionTellsTheVault_ARequestNeverApprovedDoesNot(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	rot := &fakeRotator{}
	now := time.Now().UTC()
	svc := application.NewSessionBrokerService(store, &fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithAfterUseRotation(rot)
	ctx := context.Background()
	for _, s := range []*domain.Session{
		{ID: "s_terminated", Status: domain.StatusActive, RequestedBy: "u1", PrivilegedAccountID: "acc_a", ExpiresAt: now.Add(time.Hour)},
		{ID: "s_expired", Status: domain.StatusActive, RequestedBy: "u1", PrivilegedAccountID: "acc_b", ExpiresAt: now.Add(-time.Minute)},
		{ID: "s_breakglass_used", Status: domain.StatusActive, BreakGlass: true, DecidedBy: "u2", RequestedBy: "u1", PrivilegedAccountID: "acc_c", ExpiresAt: now.Add(-time.Minute)},
		{ID: "s_request_never_approved", Status: domain.StatusPendingApproval, BreakGlass: true, RequestedBy: "u1", PrivilegedAccountID: "acc_d", ExpiresAt: now.Add(-time.Minute)},
	} {
		_ = store.Save(ctx, s)
	}
	if _, err := svc.TerminateSession(ctx, "s_terminated", "u1", nil); err != nil {
		t.Fatal(err)
	}
	if _, _, err := svc.ExpireDue(ctx); err != nil {
		t.Fatal(err)
	}
	got := rot.seen(t, 3)
	time.Sleep(50 * time.Millisecond)
	if len(got) != 3 || got[0] != "acc_a/s_terminated" || got[1] != "acc_b/s_expired" || got[2] != "acc_c/s_breakglass_used" {
		t.Fatalf("the Vault was told %v, want the three granted sessions and not the request no one approved", got)
	}
}

// ADR-0044: a notice the Vault did not get stays owed, and is sent again — with the end of the
// session it is about — until the Vault has it; then nothing more is sent.
func TestAfterUse_ANoticeTheVaultDidNotGetIsSentAgain_UntilItHasIt(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	rot := &fakeRotator{down: true}
	clock := time.Now().UTC()
	svc := application.NewSessionBrokerService(store, &fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithAfterUseRotation(rot).WithClock(func() time.Time { return clock })
	ctx := context.Background()
	_ = store.Save(ctx, &domain.Session{ID: "s1", Status: domain.StatusActive, RequestedBy: "u1", PrivilegedAccountID: "acc_a", ExpiresAt: clock.Add(time.Hour)})
	if _, err := svc.TerminateSession(ctx, "s1", "u1", nil); err != nil {
		t.Fatal(err)
	}
	ended := clock
	rot.seen(t, 1) // the first attempt, refused
	time.Sleep(20 * time.Millisecond)
	if s, _ := store.Get(ctx, "s1"); !s.AfterUseOwed {
		t.Fatal("a notice the Vault did not get is not owed")
	}

	// Within a minute of the end, it is not sent again: the first attempt has its chance.
	if d, f, err := svc.DeliverAfterUse(ctx); err != nil || d+f != 0 {
		t.Fatalf("sent again at once: %d %d %v", d, f, err)
	}
	// Later, the Vault still down: sent, still owed.
	clock = clock.Add(2 * time.Minute)
	if d, f, _ := svc.DeliverAfterUse(ctx); d != 0 || f != 1 {
		t.Fatalf("with the Vault down: %d delivered, %d failed", d, f)
	}
	// The Vault back: delivered, with the end of the session — then nothing more.
	rot.setDown(false)
	if d, f, _ := svc.DeliverAfterUse(ctx); d != 1 || f != 0 {
		t.Fatalf("with the Vault back: %d delivered, %d failed", d, f)
	}
	rot.mu.Lock()
	got := rot.ended["s1"]
	rot.mu.Unlock()
	if !got.Equal(ended) {
		t.Fatalf("the notice says the session ended at %v, want %v", got, ended)
	}
	if s, _ := store.Get(ctx, "s1"); s.AfterUseOwed {
		t.Fatal("a delivered notice is still owed")
	}
	calls := rot.count()
	if d, f, _ := svc.DeliverAfterUse(ctx); d+f != 0 || rot.count() != calls {
		t.Fatalf("a delivered notice was sent again: %d %d", d, f)
	}
}

// A notice the Vault gets at once is not owed afterwards.
func TestAfterUse_ANoticeDeliveredAtOnceIsNotOwed(t *testing.T) {
	store := infrastructure.NewInMemoryStore()
	rot := &fakeRotator{}
	svc := application.NewSessionBrokerService(store, &fakeAuthz{allowed: true}, &fakeVaultAuthorizer{}, &fakeAudit{}, &fakeAccountLookup{}, &fakeProxyClient{}).
		WithAfterUseRotation(rot)
	ctx := context.Background()
	_ = store.Save(ctx, &domain.Session{ID: "s1", Status: domain.StatusActive, RequestedBy: "u1", PrivilegedAccountID: "acc_a", ExpiresAt: time.Now().Add(time.Hour)})
	if _, err := svc.TerminateSession(ctx, "s1", "u1", nil); err != nil {
		t.Fatal(err)
	}
	rot.seen(t, 1)
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if s, _ := store.Get(ctx, "s1"); !s.AfterUseOwed {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("a notice the Vault got is still owed")
}

package application_test

// Rotation after use (ADR-0037): a granted session that ends tells the Vault; a request no one
// approved was never used, and does not.

import (
	"context"
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
}

func (f *fakeRotator) RotateAfterUse(_ context.Context, accountID, sessionID string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, accountID+"/"+sessionID)
	return nil
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

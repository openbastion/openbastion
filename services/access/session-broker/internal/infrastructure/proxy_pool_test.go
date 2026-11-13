package infrastructure_test

// ADR-0046: a ticket is issued by one instance, in turn; a revocation is asked of all of them, and
// is one only if every one confirms.

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

type fakeInstance struct {
	name        string
	mu          sync.Mutex
	establishes int
	revokes     []string
	establishEr error
	revokeErr   error
	revokeDelay time.Duration
}

func (f *fakeInstance) EstablishSession(_ context.Context, sessionID, _, _, _, _ string, _ time.Duration, _ bool, _ domain.ClipboardRights) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.establishes++
	if f.establishEr != nil {
		return "", "", f.establishEr
	}
	return f.name + ":2222", "ticket-from-" + f.name, nil
}

func (f *fakeInstance) RevokeSession(_ context.Context, sessionID string, _ time.Duration) error {
	time.Sleep(f.revokeDelay)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.revokes = append(f.revokes, sessionID)
	return f.revokeErr
}

func pool(t *testing.T, fs ...*fakeInstance) *infrastructure.ProxyPool {
	t.Helper()
	var in []infrastructure.ProxyInstance
	for _, f := range fs {
		in = append(in, infrastructure.ProxyInstance{Name: "https://" + f.name, Client: f})
	}
	p, err := infrastructure.NewProxyPool(in)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestProxyPool_ARevocationIsAskedOfEveryInstance(t *testing.T) {
	a, b, c := &fakeInstance{name: "a"}, &fakeInstance{name: "b"}, &fakeInstance{name: "c"}
	if err := pool(t, a, b, c).RevokeSession(context.Background(), "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	for _, f := range []*fakeInstance{a, b, c} {
		if len(f.revokes) != 1 || f.revokes[0] != "s1" {
			t.Fatalf("instance %s was asked %v, want [s1]", f.name, f.revokes)
		}
	}
}

func TestProxyPool_OneInstanceThatDoesNotConfirm_IsNoRevocation(t *testing.T) {
	// The attack this closes: two instances, the operator on the second; a revocation that
	// reached the first only would end a session that is still open.
	for _, failing := range []int{0, 1, 2} {
		fs := []*fakeInstance{{name: "a"}, {name: "b"}, {name: "c"}}
		fs[failing].revokeErr = errors.New("revoke-session: status 503")
		err := pool(t, fs...).RevokeSession(context.Background(), "s1", time.Minute)
		if err == nil {
			t.Fatalf("instance %d did not confirm, and the revocation was called done", failing)
		}
		if !strings.Contains(err.Error(), "1 of 3") || !strings.Contains(err.Error(), "https://"+fs[failing].name) {
			t.Fatalf("the error does not say which instance failed: %v", err)
		}
		for _, f := range fs {
			if len(f.revokes) != 1 {
				t.Fatalf("instance %s was asked %d times: every instance is asked even when one fails", f.name, len(f.revokes))
			}
		}
	}
}

func TestProxyPool_TheInstancesAreAskedAtOnce(t *testing.T) {
	slow := 200 * time.Millisecond
	fs := []*fakeInstance{{name: "a", revokeDelay: slow}, {name: "b", revokeDelay: slow}, {name: "c", revokeDelay: slow}}
	start := time.Now()
	if err := pool(t, fs...).RevokeSession(context.Background(), "s1", time.Minute); err != nil {
		t.Fatal(err)
	}
	if d := time.Since(start); d >= 2*slow {
		t.Fatalf("three instances of %s each took %s: they were asked one after the other", slow, d)
	}
}

func TestProxyPool_TicketsAreIssuedInTurn_AndTheEndpointIsTheIssuers(t *testing.T) {
	a, b, c := &fakeInstance{name: "a"}, &fakeInstance{name: "b"}, &fakeInstance{name: "c"}
	p := pool(t, a, b, c)
	var got []string
	for i := 0; i < 6; i++ {
		endpoint, ticket, err := p.EstablishSession(context.Background(), fmt.Sprint("s", i), "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
		if err != nil {
			t.Fatal(err)
		}
		if strings.TrimSuffix(endpoint, ":2222") != strings.TrimPrefix(ticket, "ticket-from-") {
			t.Fatalf("endpoint %s for a ticket of %s: the operator would be sent where the ticket is unknown", endpoint, ticket)
		}
		got = append(got, endpoint)
	}
	if strings.Join(got, ",") != "a:2222,b:2222,c:2222,a:2222,b:2222,c:2222" {
		t.Fatalf("issued by %v, want each instance in turn", got)
	}
}

func TestProxyPool_AnInstanceThatFailsIsPassed_EachAskedAtMostOnce(t *testing.T) {
	a, b, c := &fakeInstance{name: "a", establishEr: errors.New("dial tcp: refused")}, &fakeInstance{name: "b"}, &fakeInstance{name: "c"}
	endpoint, _, err := pool(t, a, b, c).EstablishSession(context.Background(), "s", "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
	if err != nil || endpoint != "b:2222" {
		t.Fatalf("endpoint %q, err %v: the next instance should have issued it", endpoint, err)
	}
	all := []*fakeInstance{{name: "a", establishEr: errors.New("x")}, {name: "b", establishEr: errors.New("y")}, {name: "c", establishEr: errors.New("z")}}
	if _, _, err := pool(t, all...).EstablishSession(context.Background(), "s", "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{}); err == nil {
		t.Fatal("no instance issued a ticket, and no error")
	}
	for _, f := range all {
		if f.establishes != 1 {
			t.Fatalf("instance %s was asked %d times, want 1", f.name, f.establishes)
		}
	}
}

func TestProxyPool_ARefusalToRecordIsWhatTheCallerIsTold(t *testing.T) {
	rec := fmt.Errorf("%w: establish-session refused by the proxy", domain.ErrRecordingUnavailable)
	fs := []*fakeInstance{{name: "a", establishEr: rec}, {name: "b", establishEr: errors.New("dial tcp: refused")}}
	_, _, err := pool(t, fs...).EstablishSession(context.Background(), "s", "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
	if !errors.Is(err, domain.ErrRecordingUnavailable) {
		t.Fatalf("err = %v, want the refusal to record (ADR-0008)", err)
	}
}

func TestProxyPool_HoldsOneToSixteenInstances(t *testing.T) {
	if _, err := infrastructure.NewProxyPool(nil); err == nil {
		t.Fatal("an empty pool was accepted")
	}
	in := make([]infrastructure.ProxyInstance, infrastructure.MaxProxyInstances+1)
	for i := range in {
		in[i] = infrastructure.ProxyInstance{Name: fmt.Sprint(i), Client: &fakeInstance{}}
	}
	if _, err := infrastructure.NewProxyPool(in); err == nil {
		t.Fatalf("%d instances were accepted", len(in))
	}
	if _, err := infrastructure.NewProxyPool(in[:infrastructure.MaxProxyInstances]); err != nil {
		t.Fatalf("%d instances: %v", infrastructure.MaxProxyInstances, err)
	}
}

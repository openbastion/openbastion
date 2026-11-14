package infrastructure_test

// ADR-0046: a ticket is issued by one instance, in turn; a revocation is asked of all of them, and
// is one only if every one confirms.

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
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
	injections  int
	injectErr   error
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

func (f *fakeInstance) InjectVaultSecret(_ context.Context, sessionID, accountID, scopeToken string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.injections++
	return f.injectErr
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

func ownerIndex(sessionID string, names []string) int {
	chosen, highest := 0, uint64(0)
	for i, name := range names {
		sum := sha256.Sum256([]byte(sessionID + "\x00" + name))
		score := binary.BigEndian.Uint64(sum[:8])
		if i == 0 || score > highest {
			chosen, highest = i, score
		}
	}
	return chosen
}

func sessionForOwner(names []string, owner int) string {
	for i := 0; ; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		if ownerIndex(sessionID, names) == owner {
			return sessionID
		}
	}
}

func TestProxyPool_AssignsSessionsDeterministicallyAcrossBrokerReplicas(t *testing.T) {
	names := []string{"https://a", "https://b", "https://c"}
	instancesA := []*fakeInstance{{name: "a"}, {name: "b"}, {name: "c"}}
	instancesB := []*fakeInstance{{name: "c"}, {name: "b"}, {name: "a"}}
	p1, p2 := pool(t, instancesA...), pool(t, instancesB...)
	counts := make([]int, len(names))
	for i := 0; i < 90; i++ {
		sessionID := fmt.Sprintf("session-%d", i)
		endpoint, _, err := p1.EstablishSession(context.Background(), sessionID, "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
		if err != nil {
			t.Fatal(err)
		}
		owner := ownerIndex(sessionID, names)
		want := strings.TrimPrefix(names[owner], "https://") + ":2222"
		if endpoint != want {
			t.Fatalf("session %s endpoint=%s want deterministic owner %s", sessionID, endpoint, want)
		}
		counts[owner]++
		before := make([]int, len(instancesB))
		for j, in := range instancesB {
			before[j] = in.injections
		}
		if err := p2.InjectVaultSecret(context.Background(), sessionID, "account", "scope-inject"); err != nil {
			t.Fatal(err)
		}
		for j, in := range instancesB {
			wantCalls := before[j]
			if in.name == strings.TrimPrefix(names[owner], "https://") {
				wantCalls++
			}
			if in.injections != wantCalls {
				t.Fatalf("replica B routed session %s to %s (%d calls), owner %s; want %d", sessionID, in.name, in.injections, strings.TrimPrefix(names[owner], "https://"), wantCalls)
			}
		}
	}
	for i, count := range counts {
		if count == 0 {
			t.Fatalf("rendezvous hashing never selected %s", names[i])
		}
	}
}

func TestProxyPool_DoesNotFailOverToAnotherInstanceForAControlBoundSession(t *testing.T) {
	names := []string{"https://a", "https://b", "https://c"}
	owner := ownerIndex(sessionForOwner(names, 0), names)
	if owner != 0 {
		t.Fatal("test helper failed to select instance a")
	}
	a, b, c := &fakeInstance{name: "a", establishEr: errors.New("dial tcp: refused")}, &fakeInstance{name: "b"}, &fakeInstance{name: "c"}
	sessionID := sessionForOwner(names, 0)
	if _, _, err := pool(t, a, b, c).EstablishSession(context.Background(), sessionID, "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{}); err == nil {
		t.Fatal("unavailable deterministic owner unexpectedly fell back")
	}
	if a.establishes != 1 || b.establishes != 0 || c.establishes != 0 {
		t.Fatalf("establish attempts a=%d b=%d c=%d", a.establishes, b.establishes, c.establishes)
	}
}

func TestProxyPool_ARefusalToRecordIsWhatTheCallerIsTold(t *testing.T) {
	rec := fmt.Errorf("%w: establish-session refused by the proxy", domain.ErrRecordingUnavailable)
	fs := []*fakeInstance{{name: "a", establishEr: rec}, {name: "b", establishEr: errors.New("dial tcp: refused")}}
	sessionID := sessionForOwner([]string{"https://a", "https://b"}, 0)
	_, _, err := pool(t, fs...).EstablishSession(context.Background(), sessionID, "ssh", "h", "u", "scope", time.Minute, false, domain.ClipboardRights{})
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

func TestProxyPool_SecretInjectionUsesTheDeterministicSessionOwner(t *testing.T) {
	names := []string{"https://a", "https://b"}
	a, b := &fakeInstance{name: "a"}, &fakeInstance{name: "b"}
	sessionID := sessionForOwner(names, 1)
	p1 := pool(t, a, b)
	endpoint, _, err := p1.EstablishSession(context.Background(), sessionID, "ssh", "host:22", "root", "scope", time.Minute, false, domain.ClipboardRights{})
	if err != nil || endpoint != "b:2222" {
		t.Fatalf("establish endpoint=%q err=%v", endpoint, err)
	}
	// A second Broker replica with the same pool configuration resolves the same owner.
	c, d := &fakeInstance{name: "b"}, &fakeInstance{name: "a"}
	if err := pool(t, c, d).InjectVaultSecret(context.Background(), sessionID, "account-1", "scope-inject"); err != nil {
		t.Fatal(err)
	}
	if c.injections != 1 || d.injections != 0 {
		t.Fatalf("injection routed to b=%d a=%d", c.injections, d.injections)
	}
}

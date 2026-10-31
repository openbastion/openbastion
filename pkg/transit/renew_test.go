package transit_test

// ADR-0053: the token renews itself at half its life, says when it cannot, and never writes itself.

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

type tokenServer struct {
	srv       *httptest.Server
	mu        sync.Mutex
	ttl       int64 // seconds, as lookup-self says
	renewable bool
	renewTo   int64 // the lease renew-self gives
	renews    []time.Time
	failRenew bool
	denyLook  bool
}

func newTokenServer(t *testing.T, ttl int64, renewable bool) *tokenServer {
	t.Helper()
	ts := &tokenServer{ttl: ttl, renewable: renewable, renewTo: ttl}
	ts.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != token {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		ts.mu.Lock()
		defer ts.mu.Unlock()
		switch r.URL.Path {
		case "/v1/auth/token/lookup-self":
			if ts.denyLook {
				w.WriteHeader(http.StatusForbidden)
				_ = json.NewEncoder(w).Encode(map[string]any{"errors": []string{"permission denied"}})
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ttl": ts.ttl, "renewable": ts.renewable}})
		case "/v1/auth/token/renew-self":
			ts.renews = append(ts.renews, time.Now())
			if ts.failRenew {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"auth": map[string]any{"lease_duration": ts.renewTo, "renewable": true}})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(ts.srv.Close)
	return ts
}

func (ts *tokenServer) count() int {
	ts.mu.Lock()
	defer ts.mu.Unlock()
	return len(ts.renews)
}

type logBook struct {
	mu    sync.Mutex
	lines []string
}

func (l *logBook) logf(f string, a ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.lines = append(l.lines, fmt.Sprintf(f, a...))
}

func (l *logBook) all() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return strings.Join(l.lines, "\n")
}

func keepAlive(t *testing.T, ts *tokenServer) (*logBook, context.CancelFunc, chan struct{}) {
	t.Helper()
	c := client(t, ts.srv.URL).WithRenewFloor(50 * time.Millisecond)
	l := &logBook{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.KeepAlive(ctx, l.logf); close(done) }()
	t.Cleanup(cancel)
	return l, cancel, done
}

func TestKeepAlive_ARenewableTokenIsRenewedAtHalfItsLife_AgainAndAgain(t *testing.T) {
	ts := newTokenServer(t, 2, true)
	start := time.Now()
	l, cancel, done := keepAlive(t, ts)
	deadline := time.Now().Add(5 * time.Second)
	for ts.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	ts.mu.Lock()
	defer ts.mu.Unlock()
	if len(ts.renews) < 3 {
		t.Fatalf("%d renewals in 5 s of a 2 s token, want at least 3", len(ts.renews))
	}
	if first := ts.renews[0].Sub(start); first < 900*time.Millisecond || first > 1800*time.Millisecond {
		t.Fatalf("the first renewal came after %s, want about half of 2 s", first)
	}
	if strings.Contains(l.all(), token) {
		t.Fatal("the token is in the log")
	}
}

func TestKeepAlive_ATokenWithoutAnEnd_OrNotRenewable_IsLeftAsItIs_AndSaid(t *testing.T) {
	for name, c := range map[string]struct {
		ttl       int64
		renewable bool
		says      string
	}{
		"no end":        {0, false, "has no end"},
		"not renewable": {3600, false, "may not be renewed: it ends in 1h0m0s"},
	} {
		ts := newTokenServer(t, c.ttl, c.renewable)
		l, _, done := keepAlive(t, ts)
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatalf("%s: KeepAlive did not return", name)
		}
		if ts.count() != 0 || !strings.Contains(l.all(), c.says) {
			t.Fatalf("%s: %d renewals, log %q", name, ts.count(), l.all())
		}
	}
}

func TestKeepAlive_AFailedRenewalIsTriedAgain_AndSaid(t *testing.T) {
	ts := newTokenServer(t, 1, true)
	ts.failRenew = true
	l, cancel, done := keepAlive(t, ts)
	deadline := time.Now().Add(3 * time.Second)
	for ts.count() < 3 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	cancel()
	<-done
	if ts.count() < 3 || !strings.Contains(l.all(), "could not be renewed") || strings.Contains(l.all(), token) {
		t.Fatalf("%d attempts, log %q", ts.count(), l.all())
	}
}

func TestKeepAlive_APolicyWithoutLookupSelfIsSaid_WithWhatToGiveIt(t *testing.T) {
	ts := newTokenServer(t, 60, true)
	ts.denyLook = true
	l, _, done := keepAlive(t, ts)
	<-done
	if ts.count() != 0 || !strings.Contains(l.all(), "auth/token/lookup-self and auth/token/renew-self") {
		t.Fatalf("%d renewals, log %q", ts.count(), l.all())
	}
}

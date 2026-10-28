package proxycore

// The registry of live and revoked sessions (ADR-0018): what is cut, what is refused,
// for how long, and that nothing slips between a registration and a revocation.

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"
)

// conn registers a connection of session and gives back what the registry needs to cut it:
// the context it is run under, and the connection itself.
func conn(t *testing.T, l *LiveSessions, session string) (context.Context, *LiveConn) {
	t.Helper()
	ctx, cancel := context.WithCancelCause(context.Background())
	t.Cleanup(func() { cancel(nil) })
	c, err := l.Begin(session, cancel)
	if err != nil {
		t.Fatalf("Begin(%s): %v", session, err)
	}
	return ctx, c
}

func TestLiveSessions_RevokeCutsEveryConnectionOfTheSession_AndOnlyThatSession(t *testing.T) {
	l := NewLiveSessions()
	a1, _ := conn(t, l, "A")
	a2, _ := conn(t, l, "A")
	b, _ := conn(t, l, "B")

	rev := l.Revoke("A", time.Now().Add(time.Hour))
	if rev.Cut() != 2 {
		t.Fatalf("cut %d connections of A, want 2", rev.Cut())
	}
	for name, ctx := range map[string]context.Context{"first": a1, "second": a2} {
		if ctx.Err() == nil || !errors.Is(context.Cause(ctx), ErrSessionRevoked) {
			t.Fatalf("the %s connection of A was not cut with ErrSessionRevoked: err=%v cause=%v", name, ctx.Err(), context.Cause(ctx))
		}
	}
	if b.Err() != nil {
		t.Fatalf("a connection of another session was cut: %v", b.Err())
	}
}

func TestLiveSessions_ARevokedSessionIsRefusedUntilItWouldHaveEnded(t *testing.T) {
	l := NewLiveSessions()
	clock := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	l.Revoke("A", clock.Add(10*time.Minute))
	if !l.Revoked("A") || l.Revoked("B") {
		t.Fatalf("Revoked(A)=%v Revoked(B)=%v, want true and false: the memory is per session", l.Revoked("A"), l.Revoked("B"))
	}
	if _, err := l.Begin("A", func(error) {}); !errors.Is(err, ErrSessionRevoked) {
		t.Fatalf("Begin on a revoked session: %v, want ErrSessionRevoked", err)
	}
	if _, err := l.Begin("B", func(error) {}); err != nil {
		t.Fatalf("Begin on another session: %v", err)
	}

	clock = clock.Add(9*time.Minute + 59*time.Second)
	if !l.Revoked("A") {
		t.Fatal("the revocation was forgotten a second before the session would have ended")
	}
	clock = clock.Add(time.Second)
	if l.Revoked("A") {
		t.Fatal("the revocation is still remembered at the time the session would have ended")
	}
	if _, err := l.Begin("A", func(error) {}); err != nil {
		t.Fatalf("Begin after the memory ran out: %v — nothing can be established for it any more, there is nothing left to refuse", err)
	}
}

func TestLiveSessions_AMemoryNeverShortens_AndALaterOneExtends(t *testing.T) {
	l := NewLiveSessions()
	clock := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }

	l.Revoke("A", clock.Add(10*time.Minute))
	l.Revoke("A", clock.Add(time.Minute)) // a second call, with less time left
	clock = clock.Add(5 * time.Minute)
	if !l.Revoked("A") {
		t.Fatal("a second revocation shortened the memory of the first")
	}
	l.Revoke("A", clock.Add(30*time.Minute))
	clock = clock.Add(20 * time.Minute)
	if !l.Revoked("A") {
		t.Fatal("a later revocation did not extend the memory")
	}
}

func TestLiveSessions_RevokingTwiceIsFine_AndCutsWhatOpenedBetween(t *testing.T) {
	l := NewLiveSessions()
	first, _ := conn(t, l, "A")
	l.Revoke("A", time.Now().Add(time.Hour))
	if first.Err() == nil {
		t.Fatal("the first connection was not cut")
	}
	// A connection that registered in spite of the memory cannot exist (Begin refuses it);
	// one that was registered before and not yet cut is cut by the next call.
	rev := l.Revoke("A", time.Now().Add(time.Hour))
	if rev.Cut() != 1 {
		t.Fatalf("a second revocation signalled %d connections, want the one still registered", rev.Cut())
	}
}

func TestLiveSessions_EndForgetsTheConnection_Once(t *testing.T) {
	l := NewLiveSessions()
	_, c := conn(t, l, "A")
	if l.OpenConnections("A") != 1 {
		t.Fatalf("%d open connections, want 1", l.OpenConnections("A"))
	}
	c.End()
	c.End() // idempotent
	if l.OpenConnections("A") != 0 {
		t.Fatalf("%d open connections after End, want 0", l.OpenConnections("A"))
	}
	if rev := l.Revoke("A", time.Now().Add(time.Hour)); rev.Cut() != 0 {
		t.Fatalf("revoking a session whose connections ended cut %d, want 0", rev.Cut())
	}
}

func TestLiveSessions_WaitReturnsWhenTheRelaysEnded_AndCountsWhatIsStillOpenWhenItGivesUp(t *testing.T) {
	l := NewLiveSessions()
	_, c1 := conn(t, l, "A")
	_, c2 := conn(t, l, "A")
	rev := l.Revoke("A", time.Now().Add(time.Hour))

	// Nothing has ended: both are still open when the wait runs out.
	start := time.Now()
	if got := rev.Wait(50 * time.Millisecond); got != 2 {
		t.Fatalf("still open: %d, want 2", got)
	}
	if elapsed := time.Since(start); elapsed < 40*time.Millisecond || elapsed > 2*time.Second {
		t.Fatalf("Wait took %v for a bound of 50ms", elapsed)
	}

	// One ends: one is left.
	c1.RelayEnded()
	if got := rev.Wait(50 * time.Millisecond); got != 1 {
		t.Fatalf("still open after one ended: %d, want 1", got)
	}

	// Both end — while waiting: Wait returns at once, with none left.
	go func() { time.Sleep(20 * time.Millisecond); c2.RelayEnded() }()
	start = time.Now()
	if got := rev.Wait(5 * time.Second); got != 0 {
		t.Fatalf("still open: %d, want 0", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("Wait did not return when the last relay ended")
	}
}

func TestLiveSessions_ARevocationOfASessionWithNothingOpenIsInstant(t *testing.T) {
	rev := NewLiveSessions().Revoke("nothing-here", time.Now().Add(time.Hour))
	start := time.Now()
	if rev.Cut() != 0 || rev.Wait(5*time.Second) != 0 || time.Since(start) > time.Second {
		t.Fatalf("a session with nothing open: cut=%d, took %v", rev.Cut(), time.Since(start))
	}
}

// Whatever the order of a registration and a revocation, a connection is either refused or
// cut — never open and untouched. This is the property the single mutex is for.
func TestLiveSessions_ARegistrationAndARevocationNeverSlipPastEachOther(t *testing.T) {
	for i := 0; i < 500; i++ {
		l := NewLiveSessions()
		ctx, cancel := context.WithCancelCause(context.Background())
		var (
			wg  sync.WaitGroup
			err error
		)
		wg.Add(2)
		go func() { defer wg.Done(); _, err = l.Begin("A", cancel) }()
		go func() { defer wg.Done(); l.Revoke("A", time.Now().Add(time.Hour)) }()
		wg.Wait()
		if err == nil && ctx.Err() == nil {
			t.Fatalf("iteration %d: a connection was registered and the session revoked, and the connection was not cut", i)
		}
		if err != nil && !errors.Is(err, ErrSessionRevoked) {
			t.Fatalf("iteration %d: Begin failed with %v, want ErrSessionRevoked", i, err)
		}
		cancel(nil)
	}
}

func TestLiveSessions_ForgetsWhatHasNothingLeftToRefuse(t *testing.T) {
	l := NewLiveSessions()
	clock := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	for _, id := range []string{"old-1", "old-2", "old-3"} {
		l.Revoke(id, clock.Add(time.Minute))
	}
	clock = clock.Add(2 * time.Minute)
	l.Revoke("fresh", clock.Add(time.Hour))
	l.mu.Lock()
	n := len(l.revoked)
	l.mu.Unlock()
	if n != 1 {
		t.Fatalf("%d revocations remembered after the old ones ran out, want 1: the memory must not grow for ever", n)
	}
}

func TestLiveSessions_OpenConnectionsCountsOneSession_AndAnEmptySessionIsForgotten(t *testing.T) {
	l := NewLiveSessions()
	_, a1 := conn(t, l, "A")
	_, a2 := conn(t, l, "A")
	_, b := conn(t, l, "B")
	if a, bb := l.OpenConnections("A"), l.OpenConnections("B"); a != 2 || bb != 1 {
		t.Fatalf("open connections: A=%d B=%d, want 2 and 1", a, bb)
	}
	a1.End()
	a2.End()
	if n := l.OpenConnections("A"); n != 0 {
		t.Fatalf("A has %d open connections after both ended", n)
	}
	l.mu.Lock()
	sessions := len(l.live)
	l.mu.Unlock()
	if sessions != 1 {
		t.Fatalf("the registry holds %d sessions, want only B: a session with no connection left is forgotten, or a proxy that serves a million sessions remembers a million empty entries", sessions)
	}
	b.End()
}

// A connection that ends without ever relaying — it was refused, or failed to fetch its
// credential — must not make a revocation wait for the bound: End says it carries nothing.
func TestLiveSessions_AConnectionThatEndsWithoutARelayDoesNotMakeARevocationWait(t *testing.T) {
	l := NewLiveSessions()
	_, c := conn(t, l, "A")
	rev := l.Revoke("A", time.Now().Add(time.Hour))
	c.End() // no RelayEnded before: the path that never reached a relay

	start := time.Now()
	if got := rev.Wait(5 * time.Second); got != 0 || time.Since(start) > time.Second {
		t.Fatalf("still open: %d after %v; a connection that ended carries nothing", got, time.Since(start))
	}
}

func TestLiveSessions_RevokedUntilSaysWhenTheMemoryEnds_AndNothingOnceItDid(t *testing.T) {
	l := NewLiveSessions()
	clock := time.Date(2026, 10, 27, 10, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return clock }
	if _, ok := l.RevokedUntil("A"); ok {
		t.Fatal("a session never revoked has a memory")
	}
	l.Revoke("A", clock.Add(time.Hour))
	if until, ok := l.RevokedUntil("A"); !ok || !until.Equal(clock.Add(time.Hour)) {
		t.Fatalf("RevokedUntil = %v, %v, want one hour from now", until, ok)
	}
	clock = clock.Add(2 * time.Hour)
	if _, ok := l.RevokedUntil("A"); ok {
		t.Fatal("a memory that ended is still reported")
	}
}

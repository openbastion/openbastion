// These tests run against a real, running PostgreSQL. Skipped, not
// failed, when TEST_DATABASE_URL is unset — see /NOTES_SANDBOX.md.
// Mirrors services/vault/password-vault/internal/infrastructure/postgres_store_test.go
// and services/access/authorization/internal/infrastructure/postgres_store_test.go.
package infrastructure_test

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func testDB(t *testing.T) *sql.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set — skipping PostgreSQL-backed tests (see /NOTES_SANDBOX.md)")
	}
	db, err := infrastructure.OpenPostgres(context.Background(), dsn)
	if err != nil {
		t.Fatalf("OpenPostgres: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func uniqueID(prefix string) string {
	return fmt.Sprintf("%s_%d", prefix, time.Now().UnixNano())
}

func TestPostgresStore_SaveThenGet_RoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond) // Postgres TIMESTAMPTZ precision
	sess := &domain.Session{
		ID: uniqueID("sess"), Status: domain.StatusActive, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "incident INC-1234",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusActive || got.Protocol != "ssh" || got.RequestedBy != "jdupont" || got.Justification != "incident INC-1234" {
		t.Fatalf("unexpected round-tripped session: %+v", got)
	}
	if got.TerminatedAt != nil {
		t.Fatalf("expected a freshly created session to have no TerminatedAt, got %v", got.TerminatedAt)
	}
	if !got.CreatedAt.Equal(now) {
		t.Fatalf("CreatedAt = %v, want %v", got.CreatedAt, now)
	}
}

func TestPostgresStore_Save_IsAnUpsertNotAnInsertOnly(t *testing.T) {
	// Unlike every other store's Create in this project, SessionRepository
	// genuinely reuses Save to update an existing row in place —
	// TerminateSession reads a session back, flips Status/TerminatedAt,
	// and calls Save again with the same ID. A plain INSERT would fail
	// outright on the primary key the second time.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := &domain.Session{
		ID: uniqueID("sess-upsert"), Status: domain.StatusActive, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "upsert check",
		CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save (create): %v", err)
	}

	terminatedAt := now.Add(5 * time.Minute)
	sess.Status = domain.StatusTerminated
	sess.TerminatedAt = &terminatedAt
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save (update): %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusTerminated {
		t.Fatalf("expected status %q after the second Save, got %q", domain.StatusTerminated, got.Status)
	}
	if got.TerminatedAt == nil || !got.TerminatedAt.Equal(terminatedAt) {
		t.Fatalf("expected TerminatedAt %v, got %v", terminatedAt, got.TerminatedAt)
	}
	// RequestedBy/Justification must survive the update untouched — the
	// UPSERT's DO UPDATE SET only touches status and terminated_at.
	if got.RequestedBy != "jdupont" || got.Justification != "upsert check" {
		t.Fatalf("expected unrelated fields to survive the update, got %+v", got)
	}
}

func TestPostgresStore_Get_UnknownSessionReturnsTheSameSentinelAsInMemoryStore(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)

	_, err := store.Get(context.Background(), uniqueID("does-not-exist"))
	if !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("expected domain.ErrNotFound for an unknown session, got %v", err)
	}
}

func TestPostgresStore_Save_DeniedSessionWithNoAccountGrantRoundTrips(t *testing.T) {
	// CreateSession records a denied attempt too (Full Auditability, doc
	// 00 §2) — Status starts as StatusDenied and the session is never
	// made active. Pins that this path, not just the happy path, writes
	// cleanly.
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	now := time.Now().UTC().Truncate(time.Microsecond)
	sess := &domain.Session{
		ID: uniqueID("sess-denied"), Status: domain.StatusDenied, Protocol: "ssh",
		RequestedBy: "jdupont", PrivilegedAccountID: uniqueID("acc"), Justification: "no access",
		CreatedAt: now, ExpiresAt: now,
	}
	if err := store.Save(ctx, sess); err != nil {
		t.Fatalf("Save: %v", err)
	}

	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.Status != domain.StatusDenied {
		t.Fatalf("expected status %q, got %q", domain.StatusDenied, got.Status)
	}
}

// The break-glass mark (ADR-0009) is part of the session and survives storage —
// and, like everything else about a session, a refused attempt keeps it.
func TestPostgresStore_BreakGlassMarkRoundTrips(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, marked := range []bool{true, false} {
		sess := &domain.Session{
			ID: uniqueID("sess-bg"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "oncall",
			PrivilegedAccountID: uniqueID("acc"), Justification: "recorder down during P1", BreakGlass: marked,
			CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		}
		if err := store.Save(ctx, sess); err != nil {
			t.Fatal(err)
		}
		// Saving again (a termination, say) must not reset the mark.
		sess.Status = domain.StatusTerminated
		if err := store.Save(ctx, sess); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(ctx, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if got.BreakGlass != marked {
			t.Fatalf("BreakGlass = %v after a round trip, want %v", got.BreakGlass, marked)
		}
	}
}

// A database created before break-glass existed has a sessions table without the
// column. Starting the new Session Broker against it must upgrade it — and the
// sessions already in it were never authorised to waive recording.
func TestPostgresStore_AnOlderDatabaseIsUpgradedInPlace(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	store := infrastructure.NewPostgresStore(db)
	old := &domain.Session{
		ID: uniqueID("sess-old"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "jdupont",
		PrivilegedAccountID: uniqueID("acc"), Justification: "before break-glass", CreatedAt: now, ExpiresAt: now.Add(time.Hour),
	}
	if err := store.Save(ctx, old); err != nil {
		t.Fatal(err)
	}

	// Take the schema back to what an older deployment has.
	if _, err := db.ExecContext(ctx, `ALTER TABLE sessions DROP COLUMN break_glass`); err != nil {
		t.Fatalf("dropping the column to simulate an older database: %v", err)
	}
	// A deployment that old predates versioned migrations too (ADR-0030): it has no row in
	// schema_migrations, so the next start runs 001_init.sql, which brings it up to date.
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE component = 'session-broker'`); err != nil {
		t.Fatal(err)
	}
	dsn := os.Getenv("TEST_DATABASE_URL")
	db2, err := infrastructure.OpenPostgres(ctx, dsn) // what the new binary does at startup
	if err != nil {
		t.Fatalf("OpenPostgres on an older database: %v", err)
	}
	defer db2.Close()

	got, err := infrastructure.NewPostgresStore(db2).Get(ctx, old.ID)
	if err != nil {
		t.Fatalf("reading a session that predates the column: %v", err)
	}
	if got.BreakGlass {
		t.Fatal("a session created before break-glass existed reads back as break-glass")
	}
	// And the upgrade is idempotent: a second start changes nothing and fails nothing.
	db3, err := infrastructure.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("second OpenPostgres: %v", err)
	}
	_ = db3.Close()
}

// -- the double validation of break-glass (ADR-0011) ---------------------------------

// What a decision changes survives storage: the new end of the session, who decided, when.
func TestPostgresStore_ADecisionRoundTrips(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()

	req := pendingRequest(uniqueID("sess-req"))
	req.CreatedAt = req.CreatedAt.Truncate(time.Microsecond)
	req.ExpiresAt = req.ExpiresAt.Truncate(time.Microsecond)
	if err := store.Save(ctx, req); err != nil {
		t.Fatal(err)
	}
	got, err := store.Get(ctx, req.ID)
	if err != nil || got.Status != domain.StatusPendingApproval || got.DurationMinutes != 20 || got.DecidedBy != "" || got.DecidedAt != nil {
		t.Fatalf("a pending request read back as %+v (%v)", got, err)
	}

	decided := decidedAs(req, domain.StatusActive, "lead")
	decided.DecidedAt = ptrTime(time.Now().UTC().Truncate(time.Microsecond))
	decided.ExpiresAt = decided.DecidedAt.Add(20 * time.Minute)
	swapped, err := store.SaveIfStatus(ctx, decided, domain.StatusPendingApproval)
	if err != nil || !swapped {
		t.Fatalf("SaveIfStatus: %v %v", swapped, err)
	}
	got, err = store.Get(ctx, req.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.Status != domain.StatusActive || got.DecidedBy != "lead" || got.DecidedAt == nil || !got.DecidedAt.Equal(*decided.DecidedAt) ||
		!got.ExpiresAt.Equal(decided.ExpiresAt) || got.DurationMinutes != 20 || !got.BreakGlass || got.RequestedBy != "oncall" {
		t.Fatalf("a decision did not survive storage: %+v", got)
	}

	// Save is the way a termination is written; it must carry the decision along, and
	// must never rewrite who asked or for what.
	got.Status = domain.StatusTerminated
	if err := store.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	if again, _ := store.Get(ctx, req.ID); again.DecidedBy != "lead" || again.DurationMinutes != 20 || again.Status != domain.StatusTerminated {
		t.Fatalf("a termination lost the decision: %+v", again)
	}
}

func ptrTime(t time.Time) *time.Time { return &t }

// One UPDATE with the expected status in its WHERE clause: of several decisions racing
// for the same request — from this process or another Broker replica — one lands.
func TestPostgresStore_SaveIfStatus_OfManyRacingDecisionsExactlyOneWins(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()

	for round := 0; round < 10; round++ {
		req := pendingRequest(uniqueID("sess-race"))
		req.CreatedAt, req.ExpiresAt = req.CreatedAt.Truncate(time.Microsecond), req.ExpiresAt.Truncate(time.Microsecond)
		if err := store.Save(ctx, req); err != nil {
			t.Fatal(err)
		}
		var wg sync.WaitGroup
		var mu sync.Mutex
		var winners []string
		// Separate connections, as separate replicas would have.
		for _, by := range []string{"a", "b", "c", "d", "e", "f"} {
			by := by
			wg.Add(1)
			go func() {
				defer wg.Done()
				status := domain.StatusActive
				if by == "f" {
					status = domain.StatusDenied
				}
				ok, err := store.SaveIfStatus(ctx, decidedAs(req, status, by), domain.StatusPendingApproval)
				if err != nil {
					t.Errorf("SaveIfStatus: %v", err)
					return
				}
				if ok {
					mu.Lock()
					winners = append(winners, by)
					mu.Unlock()
				}
			}()
		}
		wg.Wait()
		if len(winners) != 1 {
			t.Fatalf("round %d: %d decisions landed (%v), want exactly one", round, len(winners), winners)
		}
		if got, _ := store.Get(ctx, req.ID); got.DecidedBy != winners[0] {
			t.Fatalf("round %d: %s won but the row says %q", round, winners[0], got.DecidedBy)
		}
	}

	// Unknown id: nothing swapped, no error.
	if ok, err := store.SaveIfStatus(ctx, pendingRequest(uniqueID("ghost")), domain.StatusPendingApproval); ok || err != nil {
		t.Fatalf("unknown id: %v %v", ok, err)
	}
}

// A database created under ADR-0009 has the break_glass column and none of the three that
// ADR-0011 adds. Starting the new Broker against it upgrades it, and what was granted under
// the earlier regime reads back as it was: no duration, and above all no decider.
func TestPostgresStore_ADatabaseFromBeforeTheDoubleValidationIsUpgradedInPlace(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db)
	now := time.Now().UTC().Truncate(time.Microsecond)

	granted := &domain.Session{
		ID: uniqueID("sess-adr9"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "oncall",
		PrivilegedAccountID: uniqueID("acc"), Justification: "granted by one person, as ADR-0009 had it", BreakGlass: true,
		CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
	}
	if err := store.Save(ctx, granted); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `ALTER TABLE sessions DROP COLUMN duration_minutes, DROP COLUMN decided_by, DROP COLUMN decided_at`); err != nil {
		t.Fatalf("taking the schema back to ADR-0009's: %v", err)
	}
	// A deployment that old predates versioned migrations too (ADR-0030): it has no row in
	// schema_migrations, so the next start runs 001_init.sql, which brings it up to date.
	if _, err := db.ExecContext(ctx, `DELETE FROM schema_migrations WHERE component = 'session-broker'`); err != nil {
		t.Fatal(err)
	}

	dsn := os.Getenv("TEST_DATABASE_URL")
	db2, err := infrastructure.OpenPostgres(ctx, dsn) // what the new binary does at startup
	if err != nil {
		t.Fatalf("OpenPostgres on an ADR-0009 database: %v", err)
	}
	defer db2.Close()
	store2 := infrastructure.NewPostgresStore(db2)

	got, err := store2.Get(ctx, granted.ID)
	if err != nil {
		t.Fatalf("reading a session that predates the columns: %v", err)
	}
	if got.DecidedBy != "" || got.DecidedAt != nil || got.DurationMinutes != 0 || !got.BreakGlass || got.Status != domain.StatusActive {
		t.Fatalf("a session granted before the double validation reads back as %+v", got)
	}

	// The upgraded database does the new work, and a second start is a no-op.
	req := pendingRequest(uniqueID("sess-new"))
	req.CreatedAt, req.ExpiresAt = req.CreatedAt.Truncate(time.Microsecond), req.ExpiresAt.Truncate(time.Microsecond)
	if err := store2.Save(ctx, req); err != nil {
		t.Fatalf("saving a pending request on the upgraded database: %v", err)
	}
	if ok, err := store2.SaveIfStatus(ctx, decidedAs(req, domain.StatusActive, "lead"), domain.StatusPendingApproval); err != nil || !ok {
		t.Fatalf("deciding on the upgraded database: %v %v", ok, err)
	}
	db3, err := infrastructure.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("second OpenPostgres: %v", err)
	}
	_ = db3.Close()
}

// A decision is written by SaveIfStatus and by nothing else: a Save — the way a
// termination is written, from a copy read earlier — does not touch who decided, when,
// or the end of the session, so it cannot rewrite a decision that was taken.
func TestPostgresStore_OnlyTheCompareAndSwapWritesADecision(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()

	req := pendingRequest(uniqueID("sess-save"))
	req.CreatedAt, req.ExpiresAt = req.CreatedAt.Truncate(time.Microsecond), req.ExpiresAt.Truncate(time.Microsecond)
	if err := store.Save(ctx, req); err != nil {
		t.Fatal(err)
	}
	decided := decidedAs(req, domain.StatusActive, "lead")
	decided.DecidedAt = ptrTime(time.Now().UTC().Truncate(time.Microsecond))
	decided.ExpiresAt = decided.DecidedAt.Add(20 * time.Minute)
	if ok, err := store.SaveIfStatus(ctx, decided, domain.StatusPendingApproval); err != nil || !ok {
		t.Fatalf("SaveIfStatus: %v %v", ok, err)
	}

	forged := *decided
	forged.DecidedBy = "mallory"
	forged.DecidedAt = ptrTime(time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond))
	forged.ExpiresAt = decided.ExpiresAt.Add(24 * time.Hour)
	if err := store.Save(ctx, &forged); err != nil {
		t.Fatal(err)
	}
	got, _ := store.Get(ctx, req.ID)
	if got.DecidedBy != "lead" || !got.DecidedAt.Equal(*decided.DecidedAt) || !got.ExpiresAt.Equal(decided.ExpiresAt) {
		t.Fatalf("a Save rewrote a decision: %+v", got)
	}
}

// ADR-0044 on a real database: an active session that expires owes the Vault its notice, a
// request that was never granted does not; a termination writes the debt with its swap; the
// debts come back with the end of each session; a delivered one is no longer owed.
func TestPostgresStore_AfterUseOwed(t *testing.T) {
	store := infrastructure.NewPostgresStore(testDB(t))
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	active, pending, ended := uniqueID("s_active"), uniqueID("s_pending"), uniqueID("s_term")
	for _, s := range []*domain.Session{
		{ID: active, Status: domain.StatusActive, RequestedBy: "u", PrivilegedAccountID: "acc_a", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{ID: pending, Status: domain.StatusPendingApproval, BreakGlass: true, RequestedBy: "u", PrivilegedAccountID: "acc_b", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(-time.Hour)},
		{ID: ended, Status: domain.StatusActive, RequestedBy: "u", PrivilegedAccountID: "acc_c", CreatedAt: now.Add(-2 * time.Hour), ExpiresAt: now.Add(time.Hour)},
	} {
		if err := store.Save(ctx, s); err != nil {
			t.Fatal(err)
		}
	}
	expiredAt := now.Add(-30 * time.Minute)
	if _, err := store.ExpireDue(ctx, expiredAt, 100000); err != nil {
		t.Fatal(err)
	}
	termAt := now.Add(-20 * time.Minute)
	s, _ := store.Get(ctx, ended)
	s.Status, s.TerminatedAt, s.AfterUseOwed = domain.StatusTerminated, &termAt, true
	if ok, err := store.SaveIfStatus(ctx, s, domain.StatusActive); err != nil || !ok {
		t.Fatalf("terminate: %v %v", ok, err)
	}
	if s, _ := store.Get(ctx, pending); s.AfterUseOwed {
		t.Fatal("a request never granted owes a notice")
	}
	owed := func(before time.Time) map[string]time.Time {
		list, err := store.AfterUseOwed(ctx, before, 100000)
		if err != nil {
			t.Fatal(err)
		}
		out := map[string]time.Time{}
		for _, n := range list {
			if n.SessionID == active || n.SessionID == pending || n.SessionID == ended {
				out[n.SessionID] = n.EndedAt
			}
		}
		return out
	}
	got := owed(now)
	if len(got) != 2 || !got[active].Equal(expiredAt) || !got[ended].Equal(termAt) {
		t.Fatalf("owed: %v (expired at %v, terminated at %v)", got, expiredAt, termAt)
	}
	if got := owed(now.Add(-25 * time.Minute)); len(got) != 1 {
		t.Fatalf("ended before -25 min: %v", got)
	}
	if err := store.MarkAfterUseDelivered(ctx, active); err != nil {
		t.Fatal(err)
	}
	if got := owed(now); len(got) != 1 || got[ended].IsZero() {
		t.Fatalf("after delivery: %v", got)
	}
}

// ADR-0067: a session on an account that requires approval keeps that mark and its ticket,
// through a decision, in Get and in the list of the requests waiting.
func TestPostgresStore_ApprovalAndTicketRoundTrip(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	sess := &domain.Session{
		ID: uniqueID("sess-ap"), Status: domain.StatusPendingApproval, Protocol: "ssh", RequestedBy: uniqueID("user"),
		PrivilegedAccountID: uniqueID("acc"), Justification: "patch", ApprovalRequired: true, Ticket: "CHG0001234",
		CreatedAt: now, ExpiresAt: now.Add(15 * time.Minute), DurationMinutes: 45,
	}
	if saved, err := store.SaveIfUnderPendingLimit(ctx, sess, 3, now); err != nil || !saved {
		t.Fatalf("SaveIfUnderPendingLimit: %v %v", saved, err)
	}
	pending, _, err := store.ListPending(ctx, now, 1000)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, p := range pending {
		if p.ID == sess.ID {
			found = p.ApprovalRequired && p.Ticket == "CHG0001234"
		}
	}
	if !found {
		t.Fatal("the list of requests waiting lost the mark or the ticket")
	}
	decided := *sess
	decided.Status = domain.StatusActive
	decided.DecidedBy = "lead"
	decided.DecidedAt = &now
	if ok, err := store.SaveIfStatus(ctx, &decided, domain.StatusPendingApproval); err != nil || !ok {
		t.Fatalf("SaveIfStatus: %v %v", ok, err)
	}
	got, err := store.Get(ctx, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if !got.ApprovalRequired || got.Ticket != "CHG0001234" || got.Status != domain.StatusActive {
		t.Fatalf("after the decision: %+v", got)
	}
}

// The clipboard rights granted at creation (ADR-0096 §1) are what connect carries to the proxy:
// each direction survives a round trip on its own column, and a later save (a termination) keeps it.
func TestPostgresStore_ClipboardRightsRoundTrip(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)

	for _, want := range []domain.ClipboardRights{{}, {ToTarget: true}, {FromTarget: true}, {ToTarget: true, FromTarget: true}} {
		sess := &domain.Session{
			ID: uniqueID("sess-clip"), Status: domain.StatusActive, Protocol: "rdp", RequestedBy: "operator",
			PrivilegedAccountID: uniqueID("acc"), Justification: "clipboard",
			ClipboardToTarget: want.ToTarget, ClipboardFromTarget: want.FromTarget,
			CreatedAt: now, ExpiresAt: now.Add(10 * time.Minute),
		}
		if err := store.Save(ctx, sess); err != nil {
			t.Fatal(err)
		}
		// A later save (a termination) from a copy whose rights differ changes neither: they are
		// fixed at creation, like who asked and for which account.
		stale := *sess
		stale.Status = domain.StatusTerminated
		stale.ClipboardToTarget, stale.ClipboardFromTarget = !want.ToTarget, !want.FromTarget
		if err := store.Save(ctx, &stale); err != nil {
			t.Fatal(err)
		}
		got, err := store.Get(ctx, sess.ID)
		if err != nil {
			t.Fatal(err)
		}
		if g := (domain.ClipboardRights{ToTarget: got.ClipboardToTarget, FromTarget: got.ClipboardFromTarget}); g != want {
			t.Fatalf("rights %+v after a round trip, want %+v", g, want)
		}
		found, err := store.SearchSessions(ctx, domain.SessionSearch{PrivilegedAccountID: sess.PrivilegedAccountID, From: now.Add(-time.Minute), To: now.Add(time.Minute)}, 10)
		if err != nil {
			t.Fatal(err)
		}
		if len(found) != 1 || found[0].ClipboardToTarget != want.ToTarget || found[0].ClipboardFromTarget != want.FromTarget {
			t.Fatalf("searched %d session(s); rights there must be %+v: %+v", len(found), want, found)
		}
	}
}

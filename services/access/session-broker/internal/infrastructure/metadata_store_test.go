package infrastructure_test

// ADR-0116 against a real PostgreSQL: what a role allowed to write the sessions table can do to a
// row, and what the Broker then does with it. Skipped without TEST_DATABASE_URL.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/infrastructure"
)

func attestedSession(t *testing.T, store *infrastructure.PostgresStore, status domain.SessionStatus) *domain.Session {
	t.Helper()
	now := time.Now().UTC()
	sess := &domain.Session{
		ID: uniqueID("sess-meta"), Status: status, Protocol: "rdp", RequestedBy: uniqueID("user"),
		PrivilegedAccountID: uniqueID("acc"), Justification: "ADR-0116", Ticket: "CHG-1",
		CreatedAt: now, ExpiresAt: now.Add(30 * time.Minute), DurationMinutes: 30, ClipboardToTarget: true,
	}
	if err := store.Save(context.Background(), sess); err != nil {
		t.Fatal(err)
	}
	return sess
}

// Every protected column, changed directly in SQL, makes the row unusable: Get, the
// compare-and-swap, a Save and the list of requests waiting all refuse it.
func TestMetadataStore_ASQLWriteToAnyProtectedColumnIsSeen(t *testing.T) {
	db := testDB(t)
	store := infrastructure.NewPostgresStore(db, testMetadataKey)
	ctx := context.Background()
	for column, set := range map[string]string{
		"status":                "status = 'terminated'",
		"protocol":              "protocol = 'ssh'",
		"requested_by":          "requested_by = 'mallory'",
		"privileged_account_id": "privileged_account_id = 'acc_root'",
		"justification":         "justification = 'nothing to see'",
		"created_at":            "created_at = created_at - interval '1 day'",
		"expires_at":            "expires_at = expires_at + interval '1 day'",
		"terminated_at":         "terminated_at = now()",
		"break_glass":           "break_glass = true",
		"duration_minutes":      "duration_minutes = 600",
		"decided_by":            "decided_by = 'mallory'",
		"decided_at":            "decided_at = now()",
		"approval_required":     "approval_required = true",
		"ticket":                "ticket = 'CHG-2'",
		"clipboard_to_target":   "clipboard_to_target = false",
		"clipboard_from_target": "clipboard_from_target = true",
		"after_use_owed":        "after_use_owed = true",
		"metadata_revision":     "metadata_revision = metadata_revision + 1",
		"metadata_key_id":       "metadata_key_id = 'other'",
		"metadata_mac":          "metadata_mac = sha256(metadata_mac)",
	} {
		t.Run(column, func(t *testing.T) {
			sess := attestedSession(t, store, domain.StatusPendingApproval)
			if _, err := db.ExecContext(ctx, `UPDATE sessions SET `+set+` WHERE id = $1`, sess.ID); err != nil {
				t.Fatal(err)
			}
			if _, err := store.Get(ctx, sess.ID); !errors.Is(err, domain.ErrMetadataIntegrity) {
				t.Fatalf("Get: %v, want ErrMetadataIntegrity", err)
			}
			decided := *sess
			decided.Status, decided.DecidedBy = domain.StatusActive, "lead"
			now := time.Now().UTC()
			decided.DecidedAt = &now
			var current string
			_ = db.QueryRowContext(ctx, `SELECT status FROM sessions WHERE id = $1`, sess.ID).Scan(&current)
			if ok, err := store.SaveIfStatus(ctx, &decided, domain.SessionStatus(current)); ok || !errors.Is(err, domain.ErrMetadataIntegrity) {
				t.Fatalf("SaveIfStatus on a forged row: %v %v", ok, err)
			}
			if err := store.Save(ctx, &decided); !errors.Is(err, domain.ErrMetadataIntegrity) {
				t.Fatalf("Save over a forged row: %v", err)
			}
			if current == string(domain.StatusPendingApproval) {
				if _, _, err := store.ListPending(ctx, time.Now(), 10000); !errors.Is(err, domain.ErrMetadataIntegrity) {
					t.Fatalf("ListPending with a forged row: %v", err)
				}
			}
			// Leave the shared table clean for the others: the forged row goes.
			_, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, sess.ID)
		})
	}
}

// A row signed under a key the Broker does not hold is refused; the previous key of a rotation still
// verifies what it signed, and the next change is signed under the current one.
func TestMetadataStore_KeysAndRotation(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	old := domain.MetadataKey{ID: "test-k0", Key: []byte("fedcba9876543210fedcba9876543210")}
	before := infrastructure.NewPostgresStore(db, old)
	sess := attestedSession(t, before, domain.StatusActive)

	if _, err := infrastructure.NewPostgresStore(db, testMetadataKey).Get(ctx, sess.ID); !errors.Is(err, domain.ErrMetadataIntegrity) {
		t.Fatalf("a row under a key not held: %v", err)
	}
	rotating := infrastructure.NewPostgresStore(db, testMetadataKey, old)
	got, err := rotating.Get(ctx, sess.ID)
	if err != nil || got.Integrity != domain.IntegrityAttested {
		t.Fatalf("the previous key during a rotation: %v %v", got, err)
	}
	got.Status = domain.StatusTerminated
	if err := rotating.Save(ctx, got); err != nil {
		t.Fatal(err)
	}
	var keyID string
	var revision int64
	_ = db.QueryRowContext(ctx, `SELECT metadata_key_id, metadata_revision FROM sessions WHERE id = $1`, sess.ID).Scan(&keyID, &revision)
	if keyID != testMetadataKey.ID || revision != 2 {
		t.Fatalf("after a change: key %q revision %d, want the current key at revision 2", keyID, revision)
	}
	if _, err := infrastructure.NewPostgresStore(db, testMetadataKey).Get(ctx, sess.ID); err != nil {
		t.Fatalf("re-signed under the current key: %v", err)
	}
}

// Every change is one revision more, and of two replicas changing the same row, both changes land,
// one after the other: no revision is reused, none is lost.
func TestMetadataStore_RevisionsAreStrictlyMonotonic(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := infrastructure.NewPostgresStore(db, testMetadataKey)
	b := infrastructure.NewPostgresStore(testDB(t), testMetadataKey)
	sess := attestedSession(t, a, domain.StatusActive)
	if sess.MetadataRevision != 1 {
		t.Fatalf("a new session at revision %d", sess.MetadataRevision)
	}
	done := make(chan error, 2)
	for _, store := range []*infrastructure.PostgresStore{a, b} {
		go func(store *infrastructure.PostgresStore) {
			s := *sess
			s.AfterUseOwed = true
			ok, err := store.SaveIfStatus(ctx, &s, domain.StatusActive)
			if err == nil && !ok {
				err = errors.New("the swap did not happen")
			}
			done <- err
		}(store)
	}
	for i := 0; i < 2; i++ {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	got, err := a.Get(ctx, sess.ID)
	if err != nil || got.MetadataRevision != 3 {
		t.Fatalf("after two changes: revision %d, %v; want 3", got.MetadataRevision, err)
	}
	if err := a.MarkAfterUseDelivered(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := a.Get(ctx, sess.ID); err != nil || got.MetadataRevision != 4 || got.AfterUseOwed {
		t.Fatalf("clearing the debt is a revision: %+v %v", got, err)
	}
}

// The expiry sweep re-signs what it expires, and a forged due row neither expires nor holds up the
// others; a forged debt asks the Vault for nothing.
func TestMetadataStore_TheSweepsSignWhatTheyChangeAndSkipWhatIsForged(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db, testMetadataKey)
	due := attestedSession(t, store, domain.StatusActive)
	forged := attestedSession(t, store, domain.StatusActive)
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET expires_at = now() - interval '1 minute' WHERE id = ANY($1)`, "{"+due.ID+","+forged.ID+"}"); err != nil {
		t.Fatal(err)
	}
	// The honest due row is written signed at an end already passed (the SQL above forged both ends:
	// the first row is replaced).
	_, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, due.ID)
	now := time.Now().UTC()
	due = &domain.Session{ID: uniqueID("sess-due"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "u", PrivilegedAccountID: uniqueID("acc"),
		Justification: "due", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	if err := store.Save(ctx, due); err != nil {
		t.Fatal(err)
	}
	expired, err := store.ExpireDue(ctx, now, 10000)
	if err != nil {
		t.Fatal(err)
	}
	var sawDue, sawForged bool
	for _, s := range expired {
		sawDue = sawDue || s.ID == due.ID
		sawForged = sawForged || s.ID == forged.ID
	}
	if !sawDue || sawForged {
		t.Fatalf("expired the honest row %v, the forged one %v", sawDue, sawForged)
	}
	got, err := store.Get(ctx, due.ID)
	if err != nil || got.Status != domain.StatusExpired || !got.AfterUseOwed || got.MetadataRevision != 2 {
		t.Fatalf("the expired row: %+v %v", got, err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET after_use_owed = true, status = 'terminated', terminated_at = now() - interval '1 minute' WHERE id = $1`, forged.ID); err != nil {
		t.Fatal(err)
	}
	owed, err := store.AfterUseOwed(ctx, time.Now().Add(time.Minute), 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range owed {
		if n.SessionID == forged.ID {
			t.Fatal("a forged debt reaches the Vault")
		}
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, forged.ID)
}

// A row from before ADR-0116 is read as legacy, read-only: never changed, never in the lists the
// Broker acts on. A forged "legacy" row is no way around the MAC: it is just as unusable.
func TestMetadataStore_ALegacyRowIsReadOnly(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	store := infrastructure.NewPostgresStore(db, testMetadataKey)
	id := uniqueID("sess-legacy")
	if _, err := db.ExecContext(ctx, `
		INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, legacy_unverified)
		VALUES ($1, 'pending_approval', 'ssh', 'someone', 'acc_x', 'from before', now(), now() + interval '1 hour', true)`, id); err != nil {
		t.Fatal(err)
	}
	defer func() { _, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE id = $1`, id) }()
	got, err := store.Get(ctx, id)
	if err != nil || got.Integrity != domain.IntegrityLegacyUnverified {
		t.Fatalf("Get: %+v %v", got, err)
	}
	if err := got.RequireAttested(); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("RequireAttested: %v", err)
	}
	decided := *got
	decided.Status = domain.StatusActive
	if ok, err := store.SaveIfStatus(ctx, &decided, domain.StatusPendingApproval); ok || !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("SaveIfStatus on a legacy row: %v %v", ok, err)
	}
	if err := store.Save(ctx, &decided); !errors.Is(err, domain.ErrMetadataUnverified) {
		t.Fatalf("Save over a legacy row: %v", err)
	}
	pending, _, err := store.ListPending(ctx, time.Now(), 10000)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range pending {
		if p.ID == id {
			t.Fatal("a legacy request is in the list of requests to decide")
		}
	}
	if n, err := store.CountPending(ctx, "someone", time.Now()); err != nil || n != 0 {
		t.Fatalf("a legacy request counts against the quota: %d %v", n, err)
	}
}

// The migration (§8) refuses to run on a database with a session still pending or active, then,
// once it has ended, marks the history legacy and lets the new rows be signed.
func TestMetadataStore_TheMigrationNeedsAMaintenanceWindow(t *testing.T) {
	db, dsn := isolatedDB(t)
	ctx := context.Background()
	// Take the schema back to before ADR-0116, with a live session in it.
	for _, q := range []string{
		`ALTER TABLE sessions DROP COLUMN metadata_revision, DROP COLUMN metadata_key_id, DROP COLUMN metadata_mac, DROP COLUMN legacy_unverified`,
		`DELETE FROM schema_migrations WHERE component = 'session-broker' AND version = 7`,
		`INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at)
		 VALUES ('live', 'active', 'ssh', 'u', 'a', 'j', now(), now() + interval '1 hour')`,
	} {
		if _, err := db.ExecContext(ctx, q); err != nil {
			t.Fatal(err)
		}
	}
	if db2, err := infrastructure.OpenPostgres(ctx, dsn); err == nil || !strings.Contains(err.Error(), "ADR-0116") {
		if db2 != nil {
			db2.Close()
		}
		t.Fatalf("the migration ran with a live session: %v", err)
	}
	if _, err := db.ExecContext(ctx, `UPDATE sessions SET status = 'terminated', terminated_at = now() WHERE id = 'live'`); err != nil {
		t.Fatal(err)
	}
	db2, err := infrastructure.OpenPostgres(ctx, dsn)
	if err != nil {
		t.Fatalf("the migration after the window: %v", err)
	}
	defer db2.Close()
	store := infrastructure.NewPostgresStore(db2, testMetadataKey)
	if got, err := store.Get(ctx, "live"); err != nil || got.Integrity != domain.IntegrityLegacyUnverified {
		t.Fatalf("the history after the migration: %+v %v", got, err)
	}
	fresh := attestedSession(t, store, domain.StatusActive)
	if got, err := store.Get(ctx, fresh.ID); err != nil || got.Integrity != domain.IntegrityAttested {
		t.Fatalf("a new session after the migration: %+v %v", got, err)
	}
}

// fakeAttestor records the heads it is asked to move, and answers what it is told to.
type fakeAttestor struct {
	mu    sync.Mutex
	heads map[string][]uint64
	fail  error
}

func (a *fakeAttestor) AttestMetadata(ctx context.Context, id string, revision uint64, digest [32]byte, keyID string) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.fail != nil {
		return a.fail
	}
	if a.heads == nil {
		a.heads = map[string][]uint64{}
	}
	a.heads[id] = append(a.heads[id], revision)
	return nil
}

func (a *fakeAttestor) of(id string) []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]uint64(nil), a.heads[id]...)
}

// ADR-0116 §5: every committed change is attested, revision after revision, with the digest of the
// row as written; a change not attested is not confirmed, and a head that refuses it is an
// integrity failure; the expiry sweep goes on without its attestations.
func TestMetadataStore_EveryChangeIsAttestedOnceCommitted(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	attestor := &fakeAttestor{}
	store := infrastructure.NewPostgresStore(db, testMetadataKey).WithAttestor(attestor)
	sess := attestedSession(t, store, domain.StatusPendingApproval)
	decided := *sess
	now := time.Now().UTC()
	decided.Status, decided.DecidedBy, decided.DecidedAt = domain.StatusActive, "lead", &now
	if ok, err := store.SaveIfStatus(ctx, &decided, domain.StatusPendingApproval); !ok || err != nil {
		t.Fatal(ok, err)
	}
	decided.Status, decided.TerminatedAt = domain.StatusTerminated, &now
	if err := store.Save(ctx, &decided); err != nil {
		t.Fatal(err)
	}
	if got := attestor.of(sess.ID); fmt.Sprint(got) != "[1 2 3]" {
		t.Fatalf("attested revisions %v, want [1 2 3]", got)
	}

	// The Audit Service down: the change is in the database, but the caller is told it is not
	// confirmed.
	attestor.fail = errors.New("connection refused")
	other := &domain.Session{ID: uniqueID("sess-unattested"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "u",
		PrivilegedAccountID: uniqueID("acc"), Justification: "j", CreatedAt: now, ExpiresAt: now.Add(time.Hour)}
	if err := store.Save(ctx, other); !errors.Is(err, domain.ErrUnavailable) {
		t.Fatalf("a change not attested: %v, want ErrUnavailable", err)
	}
	if got, err := store.Get(ctx, other.ID); err != nil || got.MetadataRevision != 1 {
		t.Fatalf("the row of a change not attested: %+v %v", got, err)
	}
	// The head refusing: the integrity error, as it is.
	attestor.fail = fmt.Errorf("%w: refused", domain.ErrMetadataIntegrity)
	if ok, err := store.SaveIfStatus(ctx, other, domain.StatusActive); ok || !errors.Is(err, domain.ErrMetadataIntegrity) {
		t.Fatalf("a head that refuses: %v %v", ok, err)
	}
	// The sweep expires and goes on, attestations or not.
	attestor.fail = errors.New("connection refused")
	due := &domain.Session{ID: uniqueID("sess-due-unattested"), Status: domain.StatusActive, Protocol: "ssh", RequestedBy: "u",
		PrivilegedAccountID: uniqueID("acc"), Justification: "j", CreatedAt: now.Add(-time.Hour), ExpiresAt: now.Add(-time.Minute)}
	attestor.fail = nil
	if err := store.Save(ctx, due); err != nil {
		t.Fatal(err)
	}
	attestor.fail = errors.New("connection refused")
	expired, err := store.ExpireDue(ctx, now, 10000)
	if err != nil {
		t.Fatalf("the sweep with the Audit Service down: %v", err)
	}
	found := false
	for _, s := range expired {
		found = found || s.ID == due.ID
	}
	if !found {
		t.Fatal("the sweep did not expire a due session with the Audit Service down")
	}
	_, _ = db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ANY($1)`, "{"+other.ID+","+due.ID+"}")
}

// fakeLedger is the Audit Service's heads as ADR-0116 §3 has them: a revision that follows the head
// (or the first) moves it; anything else is refused.
type fakeLedger struct {
	mu       sync.Mutex
	heads    map[string]domain.MetadataHead
	down     error
	tampered bool
	attested int
	asked    int
}

func (l *fakeLedger) AttestMetadata(ctx context.Context, id string, revision uint64, digest [32]byte, keyID string) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.asked++
	if l.down != nil {
		return l.down
	}
	if l.heads == nil {
		l.heads = map[string]domain.MetadataHead{}
	}
	if h, ok := l.heads[id]; ok && revision != h.Revision+1 && !(revision == h.Revision && digest == h.Digest) {
		return fmt.Errorf("%w: refused", domain.ErrMetadataIntegrity)
	}
	l.heads[id] = domain.MetadataHead{Revision: revision, Digest: digest, KeyID: keyID}
	l.attested++
	return nil
}

func (l *fakeLedger) MetadataHead(ctx context.Context, id string) (domain.MetadataHead, bool, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down != nil {
		return domain.MetadataHead{}, false, l.down
	}
	if l.tampered {
		return domain.MetadataHead{}, false, fmt.Errorf("%w: tampered", domain.ErrMetadataIntegrity)
	}
	h, ok := l.heads[id]
	return h, ok, nil
}

func (l *fakeLedger) forget(id string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.heads, id)
}

// rowState is the stored columns of a row, to put back as they were (a restored backup).
type rowState struct {
	status, mac string
	revision    int64
	terminated  sql.NullTime
}

func snapshot(t *testing.T, db *sql.DB, id string) rowState {
	t.Helper()
	var r rowState
	if err := db.QueryRow(`SELECT status, encode(metadata_mac, 'hex'), metadata_revision, terminated_at FROM sessions WHERE id = $1`, id).
		Scan(&r.status, &r.mac, &r.revision, &r.terminated); err != nil {
		t.Fatal(err)
	}
	return r
}

func restore(t *testing.T, db *sql.DB, id string, r rowState) {
	t.Helper()
	if _, err := db.Exec(`UPDATE sessions SET status = $2, metadata_mac = decode($3, 'hex'), metadata_revision = $4, terminated_at = $5 WHERE id = $1`,
		id, r.status, r.mac, r.revision, r.terminated); err != nil {
		t.Fatal(err)
	}
}

// ADR-0116 §6: the read a decision rests on compares the row with its head.
func TestMetadataStore_AReadComparesTheRowWithItsHead(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	ledger := &fakeLedger{}
	store := infrastructure.NewPostgresStore(db, testMetadataKey).WithAttestor(ledger).WithHeads(ledger)
	plain := infrastructure.NewPostgresStore(db, testMetadataKey) // writes without attesting: a lost attestation

	t.Run("the head's revision: valid", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		if got, err := store.Get(ctx, sess.ID); err != nil || got.MetadataRevision != 1 {
			t.Fatalf("%+v %v", got, err)
		}
	})
	t.Run("a backup restored over a later revision: a rollback, refused", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		before := snapshot(t, db, sess.ID)
		ended := *sess
		now := time.Now().UTC()
		ended.Status, ended.TerminatedAt = domain.StatusTerminated, &now
		if err := store.Save(ctx, &ended); err != nil {
			t.Fatal(err)
		}
		restore(t, db, sess.ID, before) // its MAC is valid: only the head tells
		if _, err := plain.Get(ctx, sess.ID); err != nil {
			t.Fatalf("the restored row's MAC: %v", err)
		}
		if _, err := store.Get(ctx, sess.ID); !errors.Is(err, domain.ErrMetadataIntegrity) {
			t.Fatalf("a rolled-back row: %v, want ErrMetadataIntegrity", err)
		}
	})
	t.Run("one revision ahead: attested now, then valid", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		ended := *sess
		ended.AfterUseOwed = true
		if ok, err := plain.SaveIfStatus(ctx, &ended, domain.StatusActive); !ok || err != nil {
			t.Fatal(ok, err)
		}
		n := ledger.attested
		if got, err := store.Get(ctx, sess.ID); err != nil || got.MetadataRevision != 2 {
			t.Fatalf("one ahead: %+v %v", got, err)
		}
		if ledger.attested != n+1 || ledger.heads[sess.ID].Revision != 2 {
			t.Fatal("the read did not attest the revision ahead")
		}
	})
	t.Run("two revisions ahead: refused", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		for i := 0; i < 2; i++ {
			next := *sess
			next.AfterUseOwed = i == 0
			if ok, err := plain.SaveIfStatus(ctx, &next, domain.StatusActive); !ok || err != nil {
				t.Fatal(ok, err)
			}
		}
		asked := ledger.asked
		if _, err := store.Get(ctx, sess.ID); !errors.Is(err, domain.ErrMetadataIntegrity) {
			t.Fatalf("two ahead: %v", err)
		}
		if ledger.asked != asked {
			t.Fatal("a row two revisions ahead was offered to the Audit Service as a repair")
		}
	})
	t.Run("no head yet: attested now", func(t *testing.T) {
		sess := attestedSession(t, plain, domain.StatusActive)
		ledger.forget(sess.ID)
		if _, err := store.Get(ctx, sess.ID); err != nil || ledger.heads[sess.ID].Revision != 1 {
			t.Fatalf("no head: %v", err)
		}
	})
	t.Run("a head the Audit Service finds altered: refused", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		ledger.tampered = true
		defer func() { ledger.tampered = false }()
		if _, err := store.Get(ctx, sess.ID); !errors.Is(err, domain.ErrMetadataIntegrity) {
			t.Fatalf("an altered head: %v", err)
		}
	})
	t.Run("the Audit Service down: refused, not trusted", func(t *testing.T) {
		sess := attestedSession(t, store, domain.StatusActive)
		ledger.down = errors.New("connection refused")
		defer func() { ledger.down = nil }()
		if _, err := store.Get(ctx, sess.ID); !errors.Is(err, domain.ErrUnavailable) {
			t.Fatalf("the Audit Service down: %v", err)
		}
	})
	t.Run("a legacy row asks nothing", func(t *testing.T) {
		id := uniqueID("sess-legacy-head")
		if _, err := db.Exec(`INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, legacy_unverified)
			VALUES ($1, 'terminated', 'ssh', 'u', 'a', 'j', now(), now(), true)`, id); err != nil {
			t.Fatal(err)
		}
		defer func() { _, _ = db.Exec(`DELETE FROM sessions WHERE id = $1`, id) }()
		ledger.down = errors.New("connection refused")
		defer func() { ledger.down = nil }()
		if got, err := store.Get(ctx, id); err != nil || got.Integrity != domain.IntegrityLegacyUnverified {
			t.Fatalf("a legacy row with the Audit Service down: %+v %v", got, err)
		}
	})
}

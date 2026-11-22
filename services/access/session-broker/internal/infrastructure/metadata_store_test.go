package infrastructure_test

// ADR-0116 against a real PostgreSQL: what a role allowed to write the sessions table can do to a
// row, and what the Broker then does with it. Skipped without TEST_DATABASE_URL.

import (
	"context"
	"errors"
	"strings"
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

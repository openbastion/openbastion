// Package infrastructure — this file implements domain.SessionRepository
// against a real PostgreSQL database (github.com/lib/pq — hosted
// directly on GitHub, no vanity-import resolution needed, unlike
// golang.org/x/*; see /NOTES_SANDBOX.md). Mirrors
// services/vault/password-vault/internal/infrastructure/postgres_store.go
// and services/access/authorization/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/migrations"
)

func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := openPool(dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	res, err := migrate.Apply(ctx, db, "session-broker", migrations.Files)
	if err != nil {
		db.Close()
		return nil, err
	}
	res.Log("session-broker", log.Printf)
	return db, nil
}

// PostgresStore keeps the sessions, each row signed (ADR-0116): its revision, the identifier of the
// key that signed it, and an HMAC-SHA-256 under a key PostgreSQL never holds. Every write locks the
// row, verifies what is there, applies the change, signs the next revision and swaps it in only if
// the revision is still the one it read; every read verifies the MAC before the row is used.
type PostgresStore struct {
	db *sql.DB
	// keys: the current key first, then the previous ones a rotation still verifies (§7).
	keys []domain.MetadataKey
	// attestor moves each session's independent head once a change is committed (§3, §5); nil:
	// none, as in the store's own tests.
	attestor domain.MetadataAttestor
	// heads reads each session's head for the reads a decision rests on (§6); nil: none.
	heads domain.MetadataHeadReader
}

// WithHeads has every Get compare the row with the session's head in the Audit Service (§6).
func (s *PostgresStore) WithHeads(h domain.MetadataHeadReader) *PostgresStore {
	s.heads = h
	return s
}

// againstHead compares an attested row with its session's head (ADR-0116 §6):
//
//   - the head's revision and digest: valid;
//   - an older revision than the head: a rollback, refused;
//   - the head's revision with another digest or key: an alteration, refused;
//   - exactly one revision ahead (a change whose attestation was lost, §5), or no head yet: the row
//     is attested now, and valid once the Audit Service has taken it;
//   - anything else, or the Audit Service not answering: refused. No cache.
func (s *PostgresStore) againstHead(ctx context.Context, sess *domain.Session) error {
	if s.heads == nil || sess.Integrity != domain.IntegrityAttested {
		return nil
	}
	head, found, err := s.heads.MetadataHead(ctx, sess.ID)
	if err != nil {
		if errors.Is(err, domain.ErrMetadataIntegrity) {
			log.Printf("session-broker: ADR-0116: the head of session %q: %v", sess.ID, err)
			return domain.ErrMetadataIntegrity
		}
		return fmt.Errorf("%w: the head of session %s cannot be read, so its row is not used (ADR-0116 §6): %v", domain.ErrUnavailable, sess.ID, err)
	}
	digest := domain.MetadataDigest(sess)
	switch {
	case found && sess.MetadataRevision == head.Revision && digest == head.Digest:
		return nil
	case !found || sess.MetadataRevision == head.Revision+1:
		return s.attest(ctx, sess)
	case sess.MetadataRevision < head.Revision:
		log.Printf("session-broker: ADR-0116: session %q is at revision %d, its head at %d: the row was rolled back, it is not used", sess.ID, sess.MetadataRevision, head.Revision)
	case sess.MetadataRevision == head.Revision:
		log.Printf("session-broker: ADR-0116: session %q at revision %d differs from its attested head: the row was altered, it is not used", sess.ID, sess.MetadataRevision)
	default:
		log.Printf("session-broker: ADR-0116: session %q is at revision %d, %d ahead of its head: it is not used", sess.ID, sess.MetadataRevision, sess.MetadataRevision-head.Revision)
	}
	return domain.ErrMetadataIntegrity
}

// WithAttestor has every committed change attested to the Audit Service (ADR-0116 §5): a change
// is confirmed to the caller only once its revision is the head.
func (s *PostgresStore) WithAttestor(a domain.MetadataAttestor) *PostgresStore {
	s.attestor = a
	return s
}

// attest moves the head of each session written to its new revision. The rows are committed: a
// failure here is a change not confirmed, which the next read of the session finds one revision
// ahead of its head (§5).
func (s *PostgresStore) attest(ctx context.Context, written ...*domain.Session) error {
	if s.attestor == nil {
		return nil
	}
	for _, sess := range written {
		if err := s.attestor.AttestMetadata(ctx, sess.ID, sess.MetadataRevision, domain.MetadataDigest(sess), s.keys[0].ID); err != nil {
			if errors.Is(err, domain.ErrMetadataIntegrity) {
				log.Printf("session-broker: ADR-0116: the audit's head refuses revision %d of session %q: %v", sess.MetadataRevision, sess.ID, err)
				return err
			}
			return fmt.Errorf("%w: revision %d of session %s is written but not attested, so not confirmed (ADR-0116 §5): %v",
				domain.ErrUnavailable, sess.MetadataRevision, sess.ID, err)
		}
	}
	return nil
}

// NewPostgresStore signs with current, and verifies rows signed with current or any of previous.
func NewPostgresStore(db *sql.DB, current domain.MetadataKey, previous ...domain.MetadataKey) *PostgresStore {
	return &PostgresStore{db: db, keys: append([]domain.MetadataKey{current}, previous...)}
}

// querier is what a *sql.DB and a *sql.Tx have in common.
type querier interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

const sessionColumns = `id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at, break_glass,
		       duration_minutes, decided_by, decided_at, after_use_owed, approval_required, ticket, clipboard_to_target, clipboard_from_target,
		       metadata_revision, metadata_key_id, metadata_mac, legacy_unverified`

// storedRow is a row as read, before its MAC is checked.
type storedRow struct {
	sess   domain.Session
	keyID  string
	mac    []byte
	legacy bool
}

type scanner interface{ Scan(dest ...any) error }

func scanRow(sc scanner, extra ...any) (*storedRow, error) {
	var r storedRow
	var status string
	var terminatedAt, decidedAt sql.NullTime
	var revision int64
	dest := []any{&r.sess.ID, &status, &r.sess.Protocol, &r.sess.RequestedBy, &r.sess.PrivilegedAccountID,
		&r.sess.Justification, &r.sess.CreatedAt, &r.sess.ExpiresAt, &terminatedAt, &r.sess.BreakGlass,
		&r.sess.DurationMinutes, &r.sess.DecidedBy, &decidedAt, &r.sess.AfterUseOwed, &r.sess.ApprovalRequired, &r.sess.Ticket,
		&r.sess.ClipboardToTarget, &r.sess.ClipboardFromTarget, &revision, &r.keyID, &r.mac, &r.legacy}
	if err := sc.Scan(append(dest, extra...)...); err != nil {
		return nil, err
	}
	r.sess.Status = domain.SessionStatus(status)
	if terminatedAt.Valid {
		r.sess.TerminatedAt = &terminatedAt.Time
	}
	if decidedAt.Valid {
		r.sess.DecidedAt = &decidedAt.Time
	}
	if revision > 0 {
		r.sess.MetadataRevision = uint64(revision)
	}
	r.sess.CreatedAt, r.sess.ExpiresAt = r.sess.CreatedAt.UTC(), r.sess.ExpiresAt.UTC()
	return &r, nil
}

// verified is the session of r once its MAC verified, or a legacy row marked as such. A row that
// does not verify is never returned: the error says so, and the log names the session.
func (s *PostgresStore) verified(r *storedRow) (*domain.Session, error) {
	sess := r.sess
	if r.legacy {
		sess.Integrity = domain.IntegrityLegacyUnverified
		return &sess, nil
	}
	if err := domain.VerifyMetadata(s.keys, r.keyID, r.mac, &sess, sess.MetadataRevision); err != nil {
		log.Printf("session-broker: ADR-0116: the metadata of session %q failed its integrity check (revision %d, key %q): the row is not used",
			sess.ID, sess.MetadataRevision, r.keyID)
		return nil, domain.ErrMetadataIntegrity
	}
	sess.Integrity = domain.IntegrityAttested
	return &sess, nil
}

// lockRow reads and locks one row for an update in tx; nil without such a row.
func (s *PostgresStore) lockRow(ctx context.Context, tx *sql.Tx, id string) (*storedRow, error) {
	r, err := scanRow(tx.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1 FOR UPDATE`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return r, err
}

// writable is the attested session of a locked row about to change: a legacy row is never changed
// (§8), a row that does not verify is never re-signed.
func (s *PostgresStore) writable(r *storedRow) (*domain.Session, error) {
	sess, err := s.verified(r)
	if err != nil {
		return nil, err
	}
	if sess.Integrity != domain.IntegrityAttested {
		return nil, domain.ErrMetadataUnverified
	}
	return sess, nil
}

// update writes next, the change of a row read at revision next.MetadataRevision, as the next
// revision, signed; the swap is on the revision read, so that no change is lost to another replica.
func (s *PostgresStore) update(ctx context.Context, q querier, next *domain.Session, extraSet string, extra ...any) error {
	domain.TruncateMetadataTimes(next)
	read := next.MetadataRevision
	revision := read + 1
	key := s.keys[0]
	mac := domain.SignMetadata(key, next, revision)
	args := []any{next.ID, int64(read), string(next.Status), next.ExpiresAt, next.TerminatedAt, next.DecidedBy, next.DecidedAt,
		next.AfterUseOwed, int64(revision), key.ID, mac}
	set := `status = $3, expires_at = $4, terminated_at = $5, decided_by = $6, decided_at = $7, after_use_owed = $8,
			metadata_revision = $9, metadata_key_id = $10, metadata_mac = $11`
	if extraSet != "" {
		for i := range extra {
			extraSet = strings.ReplaceAll(extraSet, fmt.Sprintf("?%d", i+1), fmt.Sprintf("$%d", len(args)+i+1))
		}
		set += ", " + extraSet
		args = append(args, extra...)
	}
	res, err := q.ExecContext(ctx, `UPDATE sessions SET `+set+` WHERE id = $1 AND metadata_revision = $2 AND NOT legacy_unverified`, args...)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n != 1 {
		return fmt.Errorf("session-broker: session %q changed under its lock", next.ID)
	}
	next.MetadataRevision, next.Integrity = revision, domain.IntegrityAttested
	return nil
}

// insert writes a new session as revision 1, signed.
func (s *PostgresStore) insert(ctx context.Context, q querier, sess *domain.Session) error {
	domain.TruncateMetadataTimes(sess)
	key := s.keys[0]
	mac := domain.SignMetadata(key, sess, 1)
	_, err := q.ExecContext(ctx, `
		INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at, break_glass,
			duration_minutes, decided_by, decided_at, approval_required, ticket, clipboard_to_target, clipboard_from_target, after_use_owed,
			metadata_revision, metadata_key_id, metadata_mac, legacy_unverified)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, 1, $19, $20, false)`,
		sess.ID, string(sess.Status), sess.Protocol, sess.RequestedBy, sess.PrivilegedAccountID,
		sess.Justification, sess.CreatedAt, sess.ExpiresAt, sess.TerminatedAt, sess.BreakGlass,
		sess.DurationMinutes, sess.DecidedBy, sess.DecidedAt, sess.ApprovalRequired, sess.Ticket,
		sess.ClipboardToTarget, sess.ClipboardFromTarget, sess.AfterUseOwed, key.ID, mac)
	if err != nil {
		return err
	}
	sess.MetadataRevision, sess.Integrity = 1, domain.IntegrityAttested
	return nil
}

// Save creates a session, or changes the one stored. What a change may touch is deliberately short:
// the status and the time of termination. Who asked, for which account and why are fixed at creation
// — and so is a decision on a break-glass request (ADR-0011): its end time and its decider are
// written by SaveIfStatus and by nothing else, so that "decided once" cannot be bypassed by a Save
// from a stale copy.
func (s *PostgresStore) Save(ctx context.Context, sess *domain.Session) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	written, err := s.saveTx(ctx, tx, sess)
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.attest(ctx, written)
}

// saveTx writes sess in tx and returns the row as written (what is signed and attested).
func (s *PostgresStore) saveTx(ctx context.Context, tx *sql.Tx, sess *domain.Session) (*domain.Session, error) {
	r, err := s.lockRow(ctx, tx, sess.ID)
	if err != nil {
		return nil, err
	}
	if r == nil {
		if err := s.insert(ctx, tx, sess); err != nil {
			return nil, err
		}
		written := *sess
		return &written, nil
	}
	stored, err := s.writable(r)
	if err != nil {
		return nil, err
	}
	next := *stored
	next.Status, next.TerminatedAt = sess.Status, sess.TerminatedAt
	if err := s.update(ctx, tx, &next, ""); err != nil {
		return nil, err
	}
	sess.MetadataRevision, sess.Integrity = next.MetadataRevision, next.Integrity
	return &next, nil
}

// pendingLockClass namespaces the advisory locks this store takes, so that they
// cannot collide with anyone else's in the same database.
const pendingLockClass = 0x0B7A

// CountPending is domain.SessionRepository.CountPending: an early, cheap answer that decides
// nothing (SaveIfUnderPendingLimit holds the limit).
func (s *PostgresStore) CountPending(ctx context.Context, requestedBy string, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM sessions
		WHERE status = $1 AND requested_by = $2 AND expires_at >= $3 AND NOT legacy_unverified`,
		string(domain.StatusPendingApproval), requestedBy, now).Scan(&n)
	return n, err
}

// SaveIfUnderPendingLimit counts and inserts in one transaction that first takes an
// advisory lock keyed on the requester. Without the lock, two transactions would each
// count "2 of 3" and each insert; with it, the second waits for the first to commit
// and then counts 3. The lock is per requester, so requesters never wait for one
// another, and it is held by the database, so it works across Broker replicas. It is
// released by the commit or the rollback: nothing to clean up if the Broker dies.
func (s *PostgresStore) SaveIfUnderPendingLimit(ctx context.Context, sess *domain.Session, limit int, now time.Time) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }() // a no-op once committed

	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1, hashtext($2))`, pendingLockClass, sess.RequestedBy); err != nil {
		return false, err
	}
	var n int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM sessions
		WHERE status = $1 AND requested_by = $2 AND expires_at >= $3 AND NOT legacy_unverified`,
		string(domain.StatusPendingApproval), sess.RequestedBy, now).Scan(&n); err != nil {
		return false, err
	}
	if n >= limit {
		return false, nil // the deferred Rollback ends the transaction and frees the lock
	}
	written, err := s.saveTx(ctx, tx, sess)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	if err := s.attest(ctx, written); err != nil {
		return false, err
	}
	return true, nil
}

// SaveIfStatus is the compare-and-swap of domain.SessionRepository: the row is locked, and changed
// only if its status is still the one expected, so that of two decisions on the same pending request
// exactly one goes through, whichever Broker replica they reached.
func (s *PostgresStore) SaveIfStatus(ctx context.Context, sess *domain.Session, expected domain.SessionStatus) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback() }()
	r, err := s.lockRow(ctx, tx, sess.ID)
	if err != nil || r == nil {
		return false, err
	}
	if r.sess.Status != expected {
		return false, nil
	}
	stored, err := s.writable(r)
	if err != nil {
		return false, err
	}
	next := *stored
	next.Status, next.ExpiresAt, next.TerminatedAt = sess.Status, sess.ExpiresAt, sess.TerminatedAt
	next.DecidedBy, next.DecidedAt, next.AfterUseOwed = sess.DecidedBy, sess.DecidedAt, sess.AfterUseOwed
	if err := s.update(ctx, tx, &next, ""); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	sess.MetadataRevision, sess.Integrity = next.MetadataRevision, next.Integrity
	if err := s.attest(ctx, &next); err != nil {
		return false, err
	}
	return true, nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	r, err := scanRow(s.db.QueryRowContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE id = $1`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, domain.ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	sess, err := s.verified(r)
	if err != nil {
		return nil, err
	}
	if err := s.againstHead(ctx, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

// list reads rows of sessionColumns and verifies each: one that does not verify fails the whole
// read (a list an operator acts on is not shown with a forged row in it), unless skip says the
// caller is a background sweep, which then goes on without it.
func (s *PostgresStore) list(rows *sql.Rows, skip bool) ([]*domain.Session, error) {
	defer rows.Close()
	var out []*domain.Session
	for rows.Next() {
		r, err := scanRow(rows)
		if err != nil {
			return nil, err
		}
		sess, err := s.verified(r)
		if err != nil {
			if skip {
				continue
			}
			return nil, err
		}
		out = append(out, sess)
	}
	return out, rows.Err()
}

// ListPending is domain.SessionRepository.ListPending. It asks for one row more than
// limit: that row is how the store knows there were others, and is never returned.
// The partial index of 001_init.sql serves exactly this query.
func (s *PostgresStore) ListPending(ctx context.Context, now time.Time, limit int) ([]*domain.Session, bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+sessionColumns+`
		FROM sessions
		WHERE status = $1 AND expires_at >= $2 AND NOT legacy_unverified
		ORDER BY expires_at, id
		LIMIT $3`, string(domain.StatusPendingApproval), now, limit+1)
	if err != nil {
		return nil, false, err
	}
	out, err := s.list(rows, false)
	if err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

// likePattern makes text a substring pattern for ILIKE … ESCAPE '\': no character of the text
// is a wildcard (ADR-0080).
func likePattern(text string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(text) + "%"
}

// SearchSessions is domain.SessionRepository.SearchSessions. Legacy rows are found, marked as such.
func (s *PostgresStore) SearchSessions(ctx context.Context, q domain.SessionSearch, limit int) ([]*domain.Session, error) {
	where := []string{"created_at >= $1", "created_at < $2"}
	args := []any{q.From, q.To}
	add := func(cond string, v any) {
		args = append(args, v)
		where = append(where, strings.ReplaceAll(cond, "?", fmt.Sprintf("$%d", len(args))))
	}
	if q.Text != "" {
		add(`(requested_by ILIKE ? ESCAPE '\' OR privileged_account_id ILIKE ? ESCAPE '\' OR justification ILIKE ? ESCAPE '\' OR ticket ILIKE ? ESCAPE '\')`, likePattern(q.Text))
	}
	if q.Protocol != "" {
		add("protocol = ?", q.Protocol)
	}
	if q.RequestedBy != "" {
		add("requested_by = ?", q.RequestedBy)
	}
	if q.PrivilegedAccountID != "" {
		add("privileged_account_id = ?", q.PrivilegedAccountID)
	}
	if q.BreakGlass != nil {
		add("break_glass = ?", *q.BreakGlass)
	}
	if q.After != nil {
		args = append(args, q.After.CreatedAt, q.After.ID)
		where = append(where, fmt.Sprintf("(created_at, id) < ($%d, $%d)", len(args)-1, len(args)))
	}
	args = append(args, limit)
	rows, err := s.db.QueryContext(ctx, `SELECT `+sessionColumns+` FROM sessions WHERE `+strings.Join(where, " AND ")+
		fmt.Sprintf(` ORDER BY created_at DESC, id DESC LIMIT $%d`, len(args)), args...)
	if err != nil {
		return nil, err
	}
	return s.list(rows, false)
}

// ExpireDue is domain.SessionRepository.ExpireDue: the due rows are locked with SKIP LOCKED, so that
// two replicas sweeping together never expire the same session, and a compare-and-swap racing with
// the sweep waits for its row and then finds it expired — or wins first, and the sweep no longer
// sees it (ADR-0034). Each is verified, expired and signed as its next revision (ADR-0116); a row
// that does not verify is left as it is: it is not used anyway, and does not hold up the others.
func (s *PostgresStore) ExpireDue(ctx context.Context, now time.Time, limit int) ([]*domain.Session, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT `+sessionColumns+` FROM sessions
		WHERE status IN ($1, $2) AND expires_at < $3 AND NOT legacy_unverified
		ORDER BY expires_at, id
		LIMIT $4
		FOR UPDATE SKIP LOCKED`, string(domain.StatusActive), string(domain.StatusPendingApproval), now, limit)
	if err != nil {
		return nil, err
	}
	due, err := s.list(rows, true)
	if err != nil {
		return nil, err
	}
	for _, sess := range due {
		// An active session that ends leaves the Vault to be told (ADR-0044); a request that was
		// never granted, nothing.
		sess.AfterUseOwed = sess.Status == domain.StatusActive
		sess.Status = domain.StatusExpired
		if err := s.update(ctx, tx, sess, "expired_at = ?1, expiry_audited = FALSE", now); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	// The expiries are committed and stand; a revision not attested now is found one ahead of its
	// head by the next read (§5), and does not hold up the others.
	for _, sess := range due {
		if err := s.attest(ctx, sess); err != nil {
			log.Printf("session-broker: the expiry of session %q: %v", sess.ID, err)
		}
	}
	return due, nil
}

// ExpiriesToAudit is domain.SessionRepository.ExpiriesToAudit; the partial index of
// 002_session_expiry.sql serves it.
func (s *PostgresStore) ExpiriesToAudit(ctx context.Context, before time.Time, limit int) ([]*domain.Session, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+sessionColumns+`
		FROM sessions
		WHERE status = $1 AND NOT expiry_audited AND expired_at < $2 AND NOT legacy_unverified
		ORDER BY expired_at, id
		LIMIT $3`, string(domain.StatusExpired), before, limit)
	if err != nil {
		return nil, err
	}
	return s.list(rows, true)
}

// MarkExpiryAudited is domain.SessionRepository.MarkExpiryAudited. The flag is the bookkeeping of
// the audit's delivery and grants nothing: it is not under the MAC.
func (s *PostgresStore) MarkExpiryAudited(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE sessions SET expiry_audited = TRUE WHERE id = $1`, id)
	return err
}

// AfterUseOwed is domain.SessionRepository.AfterUseOwed; the partial index of
// 003_after_use_owed.sql serves it. A session ended by termination or by expiry: its end is
// the one or the other. Only verified rows are owed: a forged debt asks the Vault for nothing.
func (s *PostgresStore) AfterUseOwed(ctx context.Context, endedBefore time.Time, limit int) ([]domain.AfterUseNotice, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+sessionColumns+`, COALESCE(terminated_at, expired_at, expires_at) AS ended_at
		FROM sessions
		WHERE after_use_owed AND COALESCE(terminated_at, expired_at, expires_at) < $1 AND NOT legacy_unverified
		ORDER BY ended_at, id
		LIMIT $2`, endedBefore, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.AfterUseNotice
	for rows.Next() {
		var ended time.Time
		r, err := scanRow(rows, &ended)
		if err != nil {
			return nil, err
		}
		sess, err := s.verified(r)
		if err != nil || !sess.AfterUseOwed {
			continue
		}
		out = append(out, domain.AfterUseNotice{SessionID: sess.ID, AccountID: sess.PrivilegedAccountID, EndedAt: ended})
	}
	return out, rows.Err()
}

// MarkAfterUseDelivered is domain.SessionRepository.MarkAfterUseDelivered: the debt is under the
// MAC, so clearing it is a new revision.
func (s *PostgresStore) MarkAfterUseDelivered(ctx context.Context, id string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	r, err := s.lockRow(ctx, tx, id)
	if err != nil || r == nil {
		return err
	}
	stored, err := s.writable(r)
	if err != nil {
		return err
	}
	if !stored.AfterUseOwed {
		return nil
	}
	next := *stored
	next.AfterUseOwed = false
	if err := s.update(ctx, tx, &next, ""); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	return s.attest(ctx, &next)
}

// Reattest re-signs under the current key up to limit rows still signed under another one (ADR-0116
// §7), and says how many it did and how many remain. Each row is verified under the key that signed
// it and compared with its head before it is signed again: a rotation never makes valid a row that
// was altered or rolled back. A row that fails either is left as it is, and logged. Once remaining
// is 0, the previous key can be withdrawn.
func (s *PostgresStore) Reattest(ctx context.Context, limit int) (reattested, remaining int, err error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer func() { _ = tx.Rollback() }()
	rows, err := tx.QueryContext(ctx, `
		SELECT `+sessionColumns+` FROM sessions
		WHERE metadata_key_id <> $1 AND NOT legacy_unverified
		ORDER BY id
		LIMIT $2
		FOR UPDATE SKIP LOCKED`, s.keys[0].ID, limit)
	if err != nil {
		return 0, 0, err
	}
	candidates, err := s.list(rows, true)
	if err != nil {
		return 0, 0, err
	}
	var done []*domain.Session
	for _, sess := range candidates {
		if err := s.againstHead(ctx, sess); err != nil {
			log.Printf("session-broker: ADR-0116: session %q is not re-signed under the current key: %v", sess.ID, err)
			continue
		}
		if err := s.update(ctx, tx, sess, ""); err != nil {
			return 0, 0, err
		}
		done = append(done, sess)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, err
	}
	for _, sess := range done {
		if err := s.attest(ctx, sess); err != nil {
			log.Printf("session-broker: the re-signed revision of session %q: %v", sess.ID, err)
		}
	}
	if err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM sessions WHERE metadata_key_id <> $1 AND NOT legacy_unverified`, s.keys[0].ID).Scan(&remaining); err != nil {
		return len(done), 0, err
	}
	return len(done), remaining, nil
}

// MetadataKeyCensus is how many signed rows each key identifier signs.
func (s *PostgresStore) MetadataKeyCensus(ctx context.Context) (map[string]int, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT metadata_key_id, count(*) FROM sessions WHERE NOT legacy_unverified GROUP BY metadata_key_id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{}
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

// HoldsMetadataKey says whether this store verifies rows signed under id.
func (s *PostgresStore) HoldsMetadataKey(id string) bool {
	for _, k := range s.keys {
		if k.ID == id {
			return true
		}
	}
	return false
}

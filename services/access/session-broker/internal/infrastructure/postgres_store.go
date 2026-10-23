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
	"time"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/services/access/session-broker/internal/domain"
	"github.com/openbastion/openbastion/services/access/session-broker/migrations"
)

func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return nil, err
	}
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := db.ExecContext(ctx, migrations.InitSQL); err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Save is an UPSERT, unlike every other store's Create in this project —
// SessionBrokerService genuinely reuses it to both create a session
// (including a denied attempt, which is still recorded — Full
// Auditability, doc 00 §2) and later update the same row in place
// (TerminateSession reads it back, flips Status/TerminatedAt, and saves
// again). See 001_init.sql's doc comment.
//
// What an update may change is deliberately short: the status and the time of
// termination. Who asked, for which account and why are fixed at creation — and so
// is a decision on a break-glass request (ADR-0011): its end time and its decider
// are written by SaveIfStatus and by nothing else, so that "decided once" cannot be
// bypassed by a Save from a stale copy.
func (s *PostgresStore) Save(ctx context.Context, sess *domain.Session) error {
	return upsertSession(ctx, s.db, sess)
}

// execer is what a *sql.DB and a *sql.Tx have in common.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func upsertSession(ctx context.Context, db execer, sess *domain.Session) error {
	_, err := db.ExecContext(ctx, `
		INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at, break_glass, duration_minutes, decided_by, decided_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			terminated_at = EXCLUDED.terminated_at`,
		sess.ID, string(sess.Status), sess.Protocol, sess.RequestedBy, sess.PrivilegedAccountID,
		sess.Justification, sess.CreatedAt, sess.ExpiresAt, sess.TerminatedAt, sess.BreakGlass,
		sess.DurationMinutes, sess.DecidedBy, sess.DecidedAt)
	return err
}

// pendingLockClass namespaces the advisory locks this store takes, so that they
// cannot collide with anyone else's in the same database.
const pendingLockClass = 0x0B7A

// CountPending is domain.SessionRepository.CountPending.
func (s *PostgresStore) CountPending(ctx context.Context, requestedBy string, now time.Time) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `
		SELECT count(*) FROM sessions
		WHERE status = $1 AND requested_by = $2 AND expires_at >= $3`,
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
		WHERE status = $1 AND requested_by = $2 AND expires_at >= $3`,
		string(domain.StatusPendingApproval), sess.RequestedBy, now).Scan(&n); err != nil {
		return false, err
	}
	if n >= limit {
		return false, nil // the deferred Rollback ends the transaction and frees the lock
	}
	if err := upsertSession(ctx, tx, sess); err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// SaveIfStatus is the compare-and-swap of domain.SessionRepository: one UPDATE
// whose WHERE clause carries the expected status, so that of two decisions on the
// same pending request PostgreSQL lets exactly one through, whichever Broker
// replica they reached.
func (s *PostgresStore) SaveIfStatus(ctx context.Context, sess *domain.Session, expected domain.SessionStatus) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE sessions SET
			status = $2, expires_at = $3, terminated_at = $4, decided_by = $5, decided_at = $6
		WHERE id = $1 AND status = $7`,
		sess.ID, string(sess.Status), sess.ExpiresAt, sess.TerminatedAt, sess.DecidedBy, sess.DecidedAt, string(expected))
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n == 1, nil
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	var sess domain.Session
	var status string
	var terminatedAt, decidedAt sql.NullTime
	row := s.db.QueryRowContext(ctx, `
		SELECT id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at, break_glass,
		       duration_minutes, decided_by, decided_at
		FROM sessions WHERE id = $1`, id)
	if err := row.Scan(&sess.ID, &status, &sess.Protocol, &sess.RequestedBy, &sess.PrivilegedAccountID,
		&sess.Justification, &sess.CreatedAt, &sess.ExpiresAt, &terminatedAt, &sess.BreakGlass,
		&sess.DurationMinutes, &sess.DecidedBy, &decidedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	sess.Status = domain.SessionStatus(status)
	if terminatedAt.Valid {
		sess.TerminatedAt = &terminatedAt.Time
	}
	if decidedAt.Valid {
		sess.DecidedAt = &decidedAt.Time
	}
	return &sess, nil
}

// ListPending is domain.SessionRepository.ListPending. It asks for one row more than
// limit: that row is how the store knows there were others, and is never returned.
// The partial index of 001_init.sql serves exactly this query.
func (s *PostgresStore) ListPending(ctx context.Context, now time.Time, limit int) ([]*domain.Session, bool, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at, break_glass,
		       duration_minutes, decided_by, decided_at
		FROM sessions
		WHERE status = $1 AND expires_at >= $2
		ORDER BY expires_at, id
		LIMIT $3`, string(domain.StatusPendingApproval), now, limit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	var out []*domain.Session
	for rows.Next() {
		var sess domain.Session
		var status string
		var terminatedAt, decidedAt sql.NullTime
		if err := rows.Scan(&sess.ID, &status, &sess.Protocol, &sess.RequestedBy, &sess.PrivilegedAccountID,
			&sess.Justification, &sess.CreatedAt, &sess.ExpiresAt, &terminatedAt, &sess.BreakGlass,
			&sess.DurationMinutes, &sess.DecidedBy, &decidedAt); err != nil {
			return nil, false, err
		}
		sess.Status = domain.SessionStatus(status)
		if terminatedAt.Valid {
			sess.TerminatedAt = &terminatedAt.Time
		}
		if decidedAt.Valid {
			sess.DecidedAt = &decidedAt.Time
		}
		out = append(out, &sess)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	if len(out) > limit {
		return out[:limit], true, nil
	}
	return out, false, nil
}

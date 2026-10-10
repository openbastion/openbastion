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
func (s *PostgresStore) Save(ctx context.Context, sess *domain.Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (id) DO UPDATE SET
			status = EXCLUDED.status,
			terminated_at = EXCLUDED.terminated_at`,
		sess.ID, string(sess.Status), sess.Protocol, sess.RequestedBy, sess.PrivilegedAccountID,
		sess.Justification, sess.CreatedAt, sess.ExpiresAt, sess.TerminatedAt)
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*domain.Session, error) {
	var sess domain.Session
	var status string
	var terminatedAt sql.NullTime
	row := s.db.QueryRowContext(ctx, `
		SELECT id, status, protocol, requested_by, privileged_account_id, justification, created_at, expires_at, terminated_at
		FROM sessions WHERE id = $1`, id)
	if err := row.Scan(&sess.ID, &status, &sess.Protocol, &sess.RequestedBy, &sess.PrivilegedAccountID,
		&sess.Justification, &sess.CreatedAt, &sess.ExpiresAt, &terminatedAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	sess.Status = domain.SessionStatus(status)
	if terminatedAt.Valid {
		sess.TerminatedAt = &terminatedAt.Time
	}
	return &sess, nil
}

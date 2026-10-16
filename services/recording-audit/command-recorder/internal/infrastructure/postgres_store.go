// Package infrastructure — this file implements domain.CommandRepository
// against a real PostgreSQL database (github.com/lib/pq). Mirrors
// services/access/session-broker/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"context"
	"database/sql"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/command-recorder/migrations"
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

// AppendBatch inserts the whole batch in one transaction, in order — the
// BIGSERIAL ids it assigns are what keep entries with the same timestamp in
// the order they were recorded.
func (s *PostgresStore) AppendBatch(ctx context.Context, entries []domain.CommandEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once committed

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO session_command_entries (session_id, ts, command) VALUES ($1, $2, $3)`)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range entries {
		if _, err := stmt.ExecContext(ctx, e.SessionID, e.Timestamp, e.Command); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *PostgresStore) ListBySession(ctx context.Context, sessionID string, page, pageSize int) ([]domain.CommandEntry, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM session_command_entries WHERE session_id = $1`, sessionID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, session_id, ts, command FROM session_command_entries
		WHERE session_id = $1
		ORDER BY ts, id
		LIMIT $2 OFFSET $3`, sessionID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := []domain.CommandEntry{}
	for rows.Next() {
		var e domain.CommandEntry
		if err := rows.Scan(&e.ID, &e.SessionID, &e.Timestamp, &e.Command); err != nil {
			return nil, 0, err
		}
		entries = append(entries, e)
	}
	return entries, total, rows.Err()
}

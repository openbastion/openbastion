// Package infrastructure — this file implements application.Store (the
// hash chain's append-only persistence port) against a real PostgreSQL
// database (github.com/lib/pq — hosted directly on GitHub, no
// vanity-import resolution needed, unlike golang.org/x/*; see
// /NOTES_SANDBOX.md). Mirrors
// services/vault/password-vault/internal/infrastructure/postgres_store.go
// and services/access/authorization/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/migrations"
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
	res, err := migrate.Apply(ctx, db, "audit-service", migrations.Files)
	if err != nil {
		db.Close()
		return nil, err
	}
	res.Log("audit-service", log.Printf)
	return db, nil
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Append(ctx context.Context, e *domain.Event) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO audit_events (id, ts, actor_id, action, resource_type, resource_id, success, prev_hash, hash, hash_version, emitter, chain_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)`,
		e.ID, e.Timestamp, nullIfEmpty(e.ActorID), e.Action, e.ResourceType, e.ResourceID, e.Success, e.PrevHash, e.Hash, e.HashVersion, e.Emitter, e.KeyID)
	return err
}

// Last returns the most recently appended event, ordered by `seq` — the
// database's own monotone insertion order (see 001_init.sql's doc
// comment on why `ts` alone cannot be trusted to break ties). nil, nil
// when the chain is empty, matching InMemoryStore.
func (s *PostgresStore) Last(ctx context.Context) (*domain.Event, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ts, actor_id, action, resource_type, resource_id, success, prev_hash, hash, hash_version, emitter, chain_key_id
		FROM audit_events ORDER BY seq DESC LIMIT 1`)
	e, err := scanEvent(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return e, nil
}

// All returns every event in insertion order (`seq` ascending) — the
// order VerifyChain depends on to re-derive the chain correctly.
func (s *PostgresStore) All(ctx context.Context) ([]*domain.Event, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, actor_id, action, resource_type, resource_id, success, prev_hash, hash, hash_version, emitter, chain_key_id
		FROM audit_events ORDER BY seq ASC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.Event
	for rows.Next() {
		e, err := scanEvent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// DeleteThrough removes, in one transaction, the events from the first through lastID — and
// only if they are exactly `expected` events (ADR-0032): otherwise nothing is deleted.
func (s *PostgresStore) DeleteThrough(ctx context.Context, lastID string, expected int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var seq int64
	if err := tx.QueryRowContext(ctx, `SELECT seq FROM audit_events WHERE id = $1`, lastID).Scan(&seq); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("event %s is not in the chain: nothing deleted", lastID)
		}
		return err
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM audit_events WHERE seq <= $1`, seq)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != int64(expected) {
		return fmt.Errorf("deleting through %s would remove %d events, not %d: nothing deleted", lastID, n, expected)
	}
	return tx.Commit()
}

// rowScanner is satisfied by both *sql.Row and *sql.Rows.
type rowScanner interface {
	Scan(dest ...any) error
}

func scanEvent(row rowScanner) (*domain.Event, error) {
	var e domain.Event
	var actorID sql.NullString
	if err := row.Scan(&e.ID, &e.Timestamp, &actorID, &e.Action, &e.ResourceType, &e.ResourceID, &e.Success, &e.PrevHash, &e.Hash, &e.HashVersion, &e.Emitter, &e.KeyID); err != nil {
		return nil, err
	}
	if actorID.Valid {
		e.ActorID = actorID.String
	}
	return &e, nil
}

func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

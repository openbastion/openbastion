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
	"encoding/json"
	"errors"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/dbpool"
	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/audit-service/migrations"
)

func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	return OpenPostgresWithPoolConfig(ctx, dsn, dbpool.Defaults())
}

// OpenPostgresWithPoolConfig applies the limits read by the service entry point (ADR-0135).
func OpenPostgresWithPoolConfig(ctx context.Context, dsn string, config dbpool.Config) (*sql.DB, error) {
	db, err := openPool(dsn, config)
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
	return appendEvent(ctx, s.db, e)
}

// AppendWithDetection commits the audit event and its detection work item together (ADR-0117).
// A transaction-scoped advisory lock makes the capacity check valid across Audit Service replicas.
func (s *PostgresStore) AppendWithDetection(ctx context.Context, e *domain.Event, catalogVersion string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `DO $$ BEGIN PERFORM pg_advisory_xact_lock(731947201); END $$`); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox`).Scan(&pending); err != nil {
		return err
	}
	if pending >= domain.SessionAlertOutboxCapacity {
		return domain.ErrSessionAlertOutboxFull
	}
	if err := appendEvent(ctx, tx, e); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_alert_detection_outbox (source_event_id, catalog_version, attempts, next_attempt_at) VALUES ($1, $2, 0, now())`, e.ID, catalogVersion); err != nil {
		return err
	}
	return tx.Commit()
}

type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

func appendEvent(ctx context.Context, db execer, e *domain.Event) error {
	eventDetails := e.Details
	if eventDetails == nil {
		eventDetails = map[string]string{}
	}
	details, err := json.Marshal(eventDetails)
	if err != nil {
		return err
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO audit_events (id, ts, actor_id, action, resource_type, resource_id, details, success, prev_hash, hash, hash_version, emitter, chain_key_id)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)`,
		e.ID, e.Timestamp, nullIfEmpty(e.ActorID), e.Action, e.ResourceType, e.ResourceID, string(details), e.Success, e.PrevHash, e.Hash, e.HashVersion, e.Emitter, e.KeyID)
	return err
}

// Last returns the most recently appended event, ordered by `seq` — the
// database's own monotone insertion order (see 001_init.sql's doc
// comment on why `ts` alone cannot be trusted to break ties). nil, nil
// when the chain is empty, matching InMemoryStore.
func (s *PostgresStore) Last(ctx context.Context) (*domain.Event, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, ts, actor_id, action, resource_type, resource_id, details, success, prev_hash, hash, hash_version, emitter, chain_key_id
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
		SELECT id, ts, actor_id, action, resource_type, resource_id, details, success, prev_hash, hash, hash_version, emitter, chain_key_id
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
	var pendingDetection int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox d JOIN audit_events e ON e.id = d.source_event_id WHERE e.seq <= $1`, seq).Scan(&pendingDetection); err != nil {
		return err
	}
	if pendingDetection > 0 {
		return fmt.Errorf("archiving through %s would remove %d source event(s) awaiting session alert detection: nothing deleted", lastID, pendingDetection)
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
	var details []byte
	if err := row.Scan(&e.ID, &e.Timestamp, &actorID, &e.Action, &e.ResourceType, &e.ResourceID, &details, &e.Success, &e.PrevHash, &e.Hash, &e.HashVersion, &e.Emitter, &e.KeyID); err != nil {
		return nil, err
	}
	if err := json.Unmarshal(details, &e.Details); err != nil {
		return nil, fmt.Errorf("decode audit event details: %w", err)
	}
	if actorID.Valid {
		e.ActorID = actorID.String
	}
	return &e, nil
}

func nullIfEmpty(s string) sql.NullString {
	return sql.NullString{String: s, Valid: s != ""}
}

// AppendAttestation is application.MetadataHeadStore.AppendAttestation: the event and the head in one
// transaction, the head locked, and moved only if it is still `previous`.
func (s *PostgresStore) AppendAttestation(ctx context.Context, e *domain.Event, head domain.MetadataHead, previous *domain.MetadataHead) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var revision int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM session_metadata_heads WHERE session_id = $1 FOR UPDATE`, head.SessionID).Scan(&revision)
	switch {
	case errors.Is(err, sql.ErrNoRows):
		if previous != nil {
			return fmt.Errorf("the head of session %s is gone: nothing written", head.SessionID)
		}
	case err != nil:
		return err
	case previous == nil || uint64(revision) != previous.Revision:
		return fmt.Errorf("the head of session %s moved: nothing written", head.SessionID)
	}
	if err := appendEvent(ctx, tx, e); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `
		INSERT INTO session_metadata_heads (session_id, revision, metadata_sha256, key_id, event_id, event_ts, prev_hash, event_hash, chain_key_id, hash_version, emitter, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, now())
		ON CONFLICT (session_id) DO UPDATE SET revision = EXCLUDED.revision, metadata_sha256 = EXCLUDED.metadata_sha256,
			key_id = EXCLUDED.key_id, event_id = EXCLUDED.event_id, event_ts = EXCLUDED.event_ts, prev_hash = EXCLUDED.prev_hash,
			event_hash = EXCLUDED.event_hash, chain_key_id = EXCLUDED.chain_key_id, hash_version = EXCLUDED.hash_version,
			emitter = EXCLUDED.emitter, updated_at = now()
		WHERE session_metadata_heads.revision = $2 - 1`,
		head.SessionID, int64(head.Revision), head.Digest, head.KeyID, head.EventID, head.EventTime, head.PrevHash, head.EventHash,
		head.ChainKeyID, head.HashVersion, head.Emitter)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 && previous != nil {
		return fmt.Errorf("the head of session %s moved: nothing written", head.SessionID)
	}
	return tx.Commit()
}

// MetadataHead is application.MetadataHeadStore.MetadataHead.
func (s *PostgresStore) MetadataHead(ctx context.Context, sessionID string) (*domain.MetadataHead, error) {
	var h domain.MetadataHead
	var revision int64
	err := s.db.QueryRowContext(ctx, `
		SELECT session_id, revision, metadata_sha256, key_id, event_id, event_ts, prev_hash, event_hash, chain_key_id, hash_version, emitter
		FROM session_metadata_heads WHERE session_id = $1`, sessionID).Scan(
		&h.SessionID, &revision, &h.Digest, &h.KeyID, &h.EventID, &h.EventTime, &h.PrevHash, &h.EventHash, &h.ChainKeyID, &h.HashVersion, &h.Emitter)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	h.Revision = uint64(revision)
	h.EventTime = h.EventTime.UTC()
	return &h, nil
}

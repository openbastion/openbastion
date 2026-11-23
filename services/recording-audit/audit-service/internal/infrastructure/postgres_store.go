// Package infrastructure — this file implements application.Store (the
// hash chain's append-only persistence port) against a real PostgreSQL
// database (github.com/lib/pq — hosted directly on GitHub, no
// vanity-import resolution needed, unlike golang.org/x/*; see
// /NOTES_SANDBOX.md). Mirrors
// services/vault/password-vault/internal/infrastructure/postgres_store.go
// and services/access/authorization/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"time"

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

func lockAuditChain(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(1329742163, 1396788308)`)
	return err
}

// checkAuditChainHead prevents a detection transaction from appending against a stale head.
func checkAuditChainHead(ctx context.Context, q interface {
	QueryRowContext(context.Context, string, ...any) *sql.Row
}, e *domain.Event) error {
	var lastHash []byte
	err := q.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastHash)
	if errors.Is(err, sql.ErrNoRows) {
		lastHash = nil
	} else if err != nil {
		return err
	}
	if !bytes.Equal(lastHash, e.PrevHash) {
		return fmt.Errorf("audit chain head moved; event was not appended")
	}
	return nil
}

// AppendWithDetection atomically stores the signed source event and its outbox reference.
// The namespaced advisory lock serializes detection-source appends and capacity checks with worker completions.
func (s *PostgresStore) AppendWithDetection(ctx context.Context, e *domain.Event, catalogVersion string, maxPending int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := lockAuditChain(ctx, tx); err != nil {
		return err
	}
	if err := checkAuditChainHead(ctx, tx, e); err != nil {
		return err
	}
	var pending int
	if err := tx.QueryRowContext(ctx, `SELECT count(*) FROM session_alert_detection_outbox`).Scan(&pending); err != nil {
		return err
	}
	if pending >= maxPending {
		return fmt.Errorf("session alert detection outbox is full")
	}
	if err := appendEvent(ctx, tx, e); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO session_alert_detection_outbox (source_event_id, catalog_version) VALUES ($1, $2)`, e.ID, catalogVersion); err != nil {
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

// PendingDetections returns due work in deterministic FIFO order.
func (s *PostgresStore) PendingDetections(ctx context.Context, limit int) ([]domain.AlertDetectionItem, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT source_event_id, catalog_version, attempts, next_attempt_at FROM session_alert_detection_outbox WHERE next_attempt_at <= now() ORDER BY created_at, source_event_id LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []domain.AlertDetectionItem
	for rows.Next() {
		var item domain.AlertDetectionItem
		if err := rows.Scan(&item.SourceEventID, &item.CatalogVersion, &item.Attempts, &item.NextAttemptAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *PostgresStore) DetectionSource(ctx context.Context, id string) (*domain.Event, error) {
	row := s.db.QueryRowContext(ctx, `SELECT id, ts, actor_id, action, resource_type, resource_id, details, success, prev_hash, hash, hash_version, emitter, chain_key_id FROM audit_events WHERE id = $1`, id)
	event, err := scanEvent(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	return event, err
}

func (s *PostgresStore) CompleteDetection(ctx context.Context, item domain.AlertDetectionItem, alert domain.SessionAlert, event *domain.Event) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version string
	err = tx.QueryRowContext(ctx, `SELECT catalog_version FROM session_alert_detection_outbox WHERE source_event_id = $1 FOR UPDATE`, item.SourceEventID).Scan(&version)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.ErrAlertDetectionAlreadyProcessed
	}
	if err != nil {
		return err
	}
	if version != item.CatalogVersion {
		return fmt.Errorf("detection catalogue version changed")
	}
	if err := lockAuditChain(ctx, tx); err != nil {
		return err
	}
	var lastHash []byte
	err = tx.QueryRowContext(ctx, `SELECT hash FROM audit_events ORDER BY seq DESC LIMIT 1`).Scan(&lastHash)
	if errors.Is(err, sql.ErrNoRows) {
		lastHash = nil
	} else if err != nil {
		return err
	}
	if !bytes.Equal(lastHash, event.PrevHash) {
		return fmt.Errorf("audit chain head moved during detection")
	}
	if err := appendEvent(ctx, tx, event); err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO session_alerts (id, rule_id, rule_version, source_event_id, session_id, severity, status, summary, detected_at, created_at, revision) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`, alert.ID, alert.RuleID, alert.RuleVersion, alert.SourceEventID, alert.SessionID, string(alert.Severity), alert.Status, alert.Summary, alert.DetectedAt, alert.CreatedAt, alert.Revision)
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM session_alert_detection_outbox WHERE source_event_id = $1`, item.SourceEventID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *PostgresStore) DiscardDetection(ctx context.Context, item domain.AlertDetectionItem) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM session_alert_detection_outbox WHERE source_event_id = $1`, item.SourceEventID)
	return err
}

func (s *PostgresStore) RetryDetection(ctx context.Context, item domain.AlertDetectionItem, code string, next time.Time) error {
	_, err := s.db.ExecContext(ctx, `UPDATE session_alert_detection_outbox SET attempts = attempts + 1, next_attempt_at = $2, last_error_code = $3 WHERE source_event_id = $1`, item.SourceEventID, next, code)
	return err
}

package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"time"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/dbpool"
	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/migrations"
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
		_ = db.Close()
		return nil, err
	}
	result, err := migrate.Apply(ctx, db, "video-recorder", migrations.Files)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	result.Log("video-recorder", log.Printf)
	return db, nil
}

type PostgresStore struct{ db *sql.DB }

func NewPostgresStore(db *sql.DB) *PostgresStore { return &PostgresStore{db: db} }

func (s *PostgresStore) BeginRecording(ctx context.Context, sessionID, keyID string, wrappedDEK []byte) error {
	if sessionID == "" || keyID == "" || len(wrappedDEK) == 0 {
		return domain.ErrInvalidSegment
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO video_recordings
		(session_id, key_id, wrapped_dek, status, last_sequence)
		VALUES ($1, $2, $3, 'incomplete', 0)`, sessionID, keyID, wrappedDEK)
	if err != nil {
		var pqErr interface{ SQLState() string }
		if errors.As(err, &pqErr) && pqErr.SQLState() == "23505" {
			return domain.ErrAlreadyExists
		}
		return fmt.Errorf("inserting video recording: %w", err)
	}
	return nil
}

func (s *PostgresStore) AppendSegment(ctx context.Context, segment domain.SegmentMetadata) error {
	if segment.SessionID == "" || segment.FirstSequence < 1 || segment.LastSequence < segment.FirstSequence ||
		segment.ObjectKey == "" || len(segment.SHA256) != 32 {
		return domain.ErrInvalidSegment
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning video segment transaction: %w", err)
	}
	defer tx.Rollback()

	var status string
	var last int64
	if err := tx.QueryRowContext(ctx, `SELECT status, last_sequence FROM video_recordings
		WHERE session_id = $1 FOR UPDATE`, segment.SessionID).Scan(&status, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return fmt.Errorf("locking video recording: %w", err)
	}
	if status != "incomplete" || segment.FirstSequence != last+1 || segment.LastSequence < segment.FirstSequence {
		return domain.ErrConflict
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO video_recording_segments
		(session_id, first_sequence, last_sequence, object_key, ciphertext_sha256)
		VALUES ($1, $2, $3, $4, $5)`, segment.SessionID, segment.FirstSequence,
		segment.LastSequence, segment.ObjectKey, segment.SHA256); err != nil {
		return fmt.Errorf("inserting video segment metadata: %w", err)
	}
	result, err := tx.ExecContext(ctx, `UPDATE video_recordings SET last_sequence = $2
		WHERE session_id = $1 AND status = 'incomplete' AND last_sequence = $3`,
		segment.SessionID, segment.LastSequence, last)
	if err != nil {
		return fmt.Errorf("updating video recording sequence: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking video recording sequence update: %w", err)
	}
	if updated != 1 {
		return domain.ErrConflict
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("committing video segment metadata: %w", err)
	}
	return nil
}

func (s *PostgresStore) CompleteRecording(ctx context.Context, sessionID string, throughSequence int64) error {
	if sessionID == "" || throughSequence < 0 {
		return domain.ErrInvalidSegment
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("beginning video completion transaction: %w", err)
	}
	defer tx.Rollback()

	var status string
	var last int64
	if err := tx.QueryRowContext(ctx, `SELECT status, last_sequence FROM video_recordings
		WHERE session_id = $1 FOR UPDATE`, sessionID).Scan(&status, &last); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return domain.ErrNotFound
		}
		return fmt.Errorf("locking video recording for completion: %w", err)
	}
	if status != "incomplete" || last != throughSequence {
		return domain.ErrConflict
	}
	result, err := tx.ExecContext(ctx, `UPDATE video_recordings SET status = 'complete', completed_at = now()
		WHERE session_id = $1 AND status = 'incomplete' AND last_sequence = $2`, sessionID, throughSequence)
	if err != nil {
		return fmt.Errorf("marking video recording complete: %w", err)
	}
	updated, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("checking video recording completion: %w", err)
	}
	if updated != 1 {
		return domain.ErrConflict
	}
	return tx.Commit()
}

func (s *PostgresStore) GetSegment(ctx context.Context, sessionID string, firstSequence int64) (domain.StoredSegment, error) {
	var out domain.StoredSegment
	err := s.db.QueryRowContext(ctx, `SELECT s.session_id, s.first_sequence, s.last_sequence,
		s.object_key, s.ciphertext_sha256, r.key_id, r.wrapped_dek, (r.status = 'complete')
		FROM video_recording_segments s
		JOIN video_recordings r ON r.session_id = s.session_id
		WHERE s.session_id = $1 AND s.first_sequence = $2`, sessionID, firstSequence).Scan(
		&out.SessionID, &out.FirstSequence, &out.LastSequence, &out.ObjectKey, &out.SHA256,
		&out.KeyID, &out.WrappedDEK, &out.Complete)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.StoredSegment{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.StoredSegment{}, fmt.Errorf("reading video segment metadata: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) GetSegmentsFrom(ctx context.Context, sessionID string, firstSequence int64, limit int) ([]domain.StoredSegment, error) {
	if limit < 1 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `SELECT s.session_id, s.first_sequence, s.last_sequence,
		s.object_key, s.ciphertext_sha256, r.key_id, r.wrapped_dek, (r.status = 'complete')
		FROM video_recording_segments s
		JOIN video_recordings r ON r.session_id = s.session_id
		WHERE s.session_id = $1 AND s.first_sequence >= $2
		ORDER BY s.first_sequence
		LIMIT $3`, sessionID, firstSequence, limit)
	if err != nil {
		return nil, fmt.Errorf("reading video segment metadata: %w", err)
	}
	defer rows.Close()
	var out []domain.StoredSegment
	for rows.Next() {
		var segment domain.StoredSegment
		if err := rows.Scan(&segment.SessionID, &segment.FirstSequence, &segment.LastSequence, &segment.ObjectKey,
			&segment.SHA256, &segment.KeyID, &segment.WrappedDEK, &segment.Complete); err != nil {
			return nil, fmt.Errorf("reading video segment metadata: %w", err)
		}
		out = append(out, segment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("reading video segment metadata: %w", err)
	}
	return out, nil
}

func (s *PostgresStore) RecordVideoEvent(ctx context.Context, event domain.VideoRecordingEvent) (domain.VideoRecordingEvent, error) {
	if event.EventID == "" || event.SessionID == "" || (event.Protocol != "vnc" && event.Protocol != "rdp") || event.AccountID == "" ||
		!((event.EventType == "secret_injection_started" && event.Source == "vault") || (event.EventType == "secret_paste_started" && event.Source == "operator")) {
		return domain.VideoRecordingEvent{}, domain.ErrInvalidSegment
	}
	var stored domain.VideoRecordingEvent
	var bytes sql.NullInt32
	var salt, sum sql.NullString
	err := s.db.QueryRowContext(ctx, `INSERT INTO video_recording_events
		(event_id, session_id, event_type, protocol, source, account_id, paste_bytes, paste_salt, paste_sha256)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		ON CONFLICT (event_id) DO NOTHING
		RETURNING event_id, session_id, event_type, protocol, source, account_id, occurred_at, paste_bytes, paste_salt, paste_sha256`,
		event.EventID, event.SessionID, event.EventType, event.Protocol, event.Source, event.AccountID,
		nullableInt(event.PasteBytes), nullableString(event.PasteSalt), nullableString(event.PasteSHA256)).Scan(
		&stored.EventID, &stored.SessionID, &stored.EventType, &stored.Protocol, &stored.Source, &stored.AccountID, &stored.OccurredAt, &bytes, &salt, &sum)
	if errors.Is(err, sql.ErrNoRows) {
		err = s.db.QueryRowContext(ctx, `SELECT event_id, session_id, event_type, protocol, source, account_id, occurred_at, paste_bytes, paste_salt, paste_sha256
			FROM video_recording_events WHERE event_id = $1`, event.EventID).Scan(
			&stored.EventID, &stored.SessionID, &stored.EventType, &stored.Protocol, &stored.Source, &stored.AccountID, &stored.OccurredAt, &bytes, &salt, &sum)
		stored.PasteBytes, stored.PasteSalt, stored.PasteSHA256 = int(bytes.Int32), salt.String, sum.String
		if err == nil && (stored.SessionID != event.SessionID || stored.EventType != event.EventType || stored.Protocol != event.Protocol || stored.Source != event.Source || stored.AccountID != event.AccountID || !stored.SamePaste(event)) {
			return domain.VideoRecordingEvent{}, domain.ErrEventConflict
		}
	}
	if err != nil {
		var pqErr interface{ SQLState() string }
		if errors.As(err, &pqErr) && pqErr.SQLState() == "23503" {
			return domain.VideoRecordingEvent{}, domain.ErrNotFound
		}
		return domain.VideoRecordingEvent{}, fmt.Errorf("recording video event: %w", err)
	}
	stored.PasteBytes, stored.PasteSalt, stored.PasteSHA256 = int(bytes.Int32), salt.String, sum.String
	return stored, nil
}

func nullableInt(value int) any {
	if value == 0 {
		return nil
	}
	return value
}

func nullableString(value string) any {
	if value == "" {
		return nil
	}
	return value
}

func (s *PostgresStore) GetVideoEvents(ctx context.Context, sessionID string, after domain.EventCursor, limit int) ([]domain.VideoRecordingEvent, error) {
	if sessionID == "" || limit < 1 {
		return nil, domain.ErrInvalidSegment
	}
	rows, err := s.db.QueryContext(ctx, `SELECT event_id, session_id, event_type, protocol, source, account_id, occurred_at, paste_bytes, paste_salt, paste_sha256
		FROM video_recording_events
		WHERE session_id = $1 AND ($2::timestamptz IS NULL OR (occurred_at, event_id) > ($2, $3))
		ORDER BY occurred_at ASC, event_id ASC LIMIT $4`, sessionID, nullableTime(after.OccurredAt), after.EventID, limit)
	if err != nil {
		return nil, fmt.Errorf("querying video recording events: %w", err)
	}
	defer rows.Close()
	out := make([]domain.VideoRecordingEvent, 0, limit)
	for rows.Next() {
		var event domain.VideoRecordingEvent
		var bytes sql.NullInt32
		var salt, sum sql.NullString
		if err := rows.Scan(&event.EventID, &event.SessionID, &event.EventType, &event.Protocol, &event.Source, &event.AccountID, &event.OccurredAt, &bytes, &salt, &sum); err != nil {
			return nil, fmt.Errorf("scanning video recording event: %w", err)
		}
		event.PasteBytes, event.PasteSalt, event.PasteSHA256 = int(bytes.Int32), salt.String, sum.String
		out = append(out, event)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating video recording events: %w", err)
	}
	return out, nil
}

func nullableTime(value time.Time) any {
	if value.IsZero() {
		return nil
	}
	return value.UTC()
}

func (s *PostgresStore) Ready(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("opening write transaction: %w", err)
	}
	defer tx.Rollback()
	var readOnly string
	var inRecovery bool
	if err := tx.QueryRowContext(ctx, `SELECT current_setting('transaction_read_only'), pg_is_in_recovery()`).Scan(&readOnly, &inRecovery); err != nil {
		return fmt.Errorf("checking PostgreSQL readiness: %w", err)
	}
	if inRecovery || readOnly != "off" {
		return errors.New("PostgreSQL is read-only")
	}
	return nil
}

var _ domain.Repository = (*PostgresStore)(nil)

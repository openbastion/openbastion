package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"

	_ "github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/internal/domain"
	"github.com/openbastion/openbastion/services/recording-audit/video-recorder/migrations"
)

func OpenPostgres(ctx context.Context, dsn string) (*sql.DB, error) {
	db, err := openPool(dsn)
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

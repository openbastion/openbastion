// Package infrastructure — this file implements domain.CommandRepository
// against a real PostgreSQL database (github.com/lib/pq), encrypting every
// command at rest (envelope.go). Mirrors
// services/access/session-broker/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

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
	db  *sql.DB
	kek KeyWrapper
}

// NewPostgresStore returns a store that seals every command under a
// per-session data key wrapped by kek. Before it returns, any plaintext rows
// left by a version of this service that predated encryption are sealed and
// their plaintext column dropped — "nothing is stored in the clear" is made
// true by construction, not by hoping no old row remains.
func NewPostgresStore(ctx context.Context, db *sql.DB, kek KeyWrapper) (*PostgresStore, error) {
	s := &PostgresStore{db: db, kek: kek}
	if err := s.sealLegacyPlaintext(ctx); err != nil {
		return nil, fmt.Errorf("sealing rows stored before encryption: %w", err)
	}
	return s, nil
}

// querier is the part of *sql.DB and *sql.Tx the key handling needs, so the
// same code serves a batch inside a transaction and a plain read.
type querier interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// loadDEK returns the unwrapped data key of a session, or found=false if the
// session has none. The caller zeroes the key when done.
func (s *PostgresStore) loadDEK(ctx context.Context, q querier, sessionID string) (dek []byte, found bool, err error) {
	var kekID string
	var wrapped []byte
	err = q.QueryRowContext(ctx, `SELECT kek_id, wrapped_dek FROM session_recording_keys WHERE session_id = $1`, sessionID).Scan(&kekID, &wrapped)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, err
	}
	if kekID != s.kek.KeyID() {
		return nil, false, fmt.Errorf("the recording key of session %q was wrapped under KEK %q, but this process holds %q", sessionID, kekID, s.kek.KeyID())
	}
	dek, err = s.kek.Unwrap(wrapped, dekAAD(kekID, sessionID))
	if err != nil {
		return nil, false, fmt.Errorf("cannot unwrap the recording key of session %q (wrong KMS_KEY_HEX, or the row was altered)", sessionID)
	}
	return dek, true, nil
}

// dekForWrite returns the session's data key, creating and storing it (wrapped)
// on first use. Two batches racing to create the same session's key are
// harmless: the insert is ON CONFLICT DO NOTHING and both then read back the
// winner's, so there is exactly one key per session.
func (s *PostgresStore) dekForWrite(ctx context.Context, q querier, sessionID string) ([]byte, error) {
	if dek, found, err := s.loadDEK(ctx, q, sessionID); err != nil || found {
		return dek, err
	}
	fresh, err := newDEK()
	if err != nil {
		return nil, err
	}
	wrapped, err := s.kek.Wrap(fresh, dekAAD(s.kek.KeyID(), sessionID))
	zero(fresh) // we always re-read the stored key below, so the winner's is the one used
	if err != nil {
		return nil, err
	}
	if _, err := q.ExecContext(ctx,
		`INSERT INTO session_recording_keys (session_id, kek_id, wrapped_dek) VALUES ($1, $2, $3) ON CONFLICT (session_id) DO NOTHING`,
		sessionID, s.kek.KeyID(), wrapped); err != nil {
		return nil, err
	}
	dek, found, err := s.loadDEK(ctx, q, sessionID)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("recording key of session %q missing right after creation", sessionID)
	}
	return dek, nil
}

// AppendBatch seals and inserts the whole batch in one transaction, in order —
// the BIGSERIAL ids it assigns are what keep entries with the same timestamp
// in the order they were recorded. A failure part-way leaves nothing behind,
// not even a key row.
func (s *PostgresStore) AppendBatch(ctx context.Context, entries []domain.CommandEntry) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() // no-op once committed

	deks := map[string][]byte{}
	defer func() {
		for _, dek := range deks {
			zero(dek)
		}
	}()

	stmt, err := tx.PrepareContext(ctx, `INSERT INTO session_command_entries (session_id, ts, command_sealed) VALUES ($1, $2, $3)`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for _, e := range entries {
		dek, ok := deks[e.SessionID]
		if !ok {
			if dek, err = s.dekForWrite(ctx, tx, e.SessionID); err != nil {
				return err
			}
			deks[e.SessionID] = dek
		}
		ts := e.Timestamp.UTC().Truncate(time.Microsecond)
		sealed, err := sealCommand(dek, e.SessionID, ts, e.Command)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx, e.SessionID, ts, sealed); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// ListBySession decrypts one page. Any entry that fails authentication — its
// ciphertext altered, its timestamp edited, or moved from another session —
// fails the whole call: a replay with a silently missing or altered line is
// worse than no replay, and the failure is the alarm.
func (s *PostgresStore) ListBySession(ctx context.Context, sessionID string, page, pageSize int) ([]domain.CommandEntry, int, error) {
	var total int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM session_command_entries WHERE session_id = $1`, sessionID).Scan(&total); err != nil {
		return nil, 0, err
	}

	rows, err := s.db.QueryContext(ctx, `
		SELECT id, ts, command_sealed FROM session_command_entries
		WHERE session_id = $1
		ORDER BY ts, id
		LIMIT $2 OFFSET $3`, sessionID, pageSize, (page-1)*pageSize)
	if err != nil {
		return nil, 0, err
	}
	type sealedRow struct {
		id     int64
		ts     time.Time
		sealed []byte
	}
	var fetched []sealedRow
	for rows.Next() {
		var r sealedRow
		if err := rows.Scan(&r.id, &r.ts, &r.sealed); err != nil {
			rows.Close()
			return nil, 0, err
		}
		fetched = append(fetched, r)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, 0, err
	}
	rows.Close()

	entries := []domain.CommandEntry{}
	if len(fetched) == 0 {
		return entries, total, nil
	}

	dek, found, err := s.loadDEK(ctx, s.db, sessionID)
	if err != nil {
		return nil, 0, err
	}
	if !found {
		return nil, 0, fmt.Errorf("session %q has recorded entries but no recording key", sessionID)
	}
	defer zero(dek)

	for _, r := range fetched {
		command, err := openCommand(dek, sessionID, r.ts, r.sealed)
		if err != nil {
			return nil, 0, fmt.Errorf("recording entry %d failed authentication (altered, moved, or sealed under another key)", r.id)
		}
		entries = append(entries, domain.CommandEntry{ID: r.id, SessionID: sessionID, Timestamp: r.ts, Command: command})
	}
	return entries, total, nil
}

// sealLegacyPlaintext upgrades a table created before encryption existed: it
// seals every plaintext row under its session's key, then drops the plaintext
// column, all in one transaction under an exclusive lock — so a second replica
// starting at the same moment waits, then finds nothing to do. On a table that
// was created with the encrypted shape it is a no-op.
func (s *PostgresStore) sealLegacyPlaintext(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if _, err := tx.ExecContext(ctx, `LOCK TABLE session_command_entries IN ACCESS EXCLUSIVE MODE`); err != nil {
		return err
	}
	var legacy int
	if err := tx.QueryRowContext(ctx, `
		SELECT count(*) FROM information_schema.columns
		WHERE table_schema = current_schema() AND table_name = 'session_command_entries' AND column_name = 'command'`).Scan(&legacy); err != nil {
		return err
	}
	if legacy == 0 {
		return tx.Commit()
	}

	if _, err := tx.ExecContext(ctx, `ALTER TABLE session_command_entries ADD COLUMN IF NOT EXISTS command_sealed BYTEA`); err != nil {
		return err
	}

	deks := map[string][]byte{}
	defer func() {
		for _, dek := range deks {
			zero(dek)
		}
	}()

	for {
		type legacyRow struct {
			id        int64
			sessionID string
			ts        time.Time
			command   string
		}
		rows, err := tx.QueryContext(ctx, `
			SELECT id, session_id, ts, command FROM session_command_entries
			WHERE command_sealed IS NULL ORDER BY id LIMIT 500`)
		if err != nil {
			return err
		}
		var batch []legacyRow
		for rows.Next() {
			var r legacyRow
			if err := rows.Scan(&r.id, &r.sessionID, &r.ts, &r.command); err != nil {
				rows.Close()
				return err
			}
			batch = append(batch, r)
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}
		rows.Close()
		if len(batch) == 0 {
			break
		}
		for _, r := range batch {
			dek, ok := deks[r.sessionID]
			if !ok {
				if dek, err = s.dekForWrite(ctx, tx, r.sessionID); err != nil {
					return err
				}
				deks[r.sessionID] = dek
			}
			ts := r.ts.UTC().Truncate(time.Microsecond)
			sealed, err := sealCommand(dek, r.sessionID, ts, r.command)
			if err != nil {
				return err
			}
			if _, err := tx.ExecContext(ctx, `UPDATE session_command_entries SET command_sealed = $1 WHERE id = $2`, sealed, r.id); err != nil {
				return err
			}
		}
	}

	if _, err := tx.ExecContext(ctx, `ALTER TABLE session_command_entries ALTER COLUMN command_sealed SET NOT NULL`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `ALTER TABLE session_command_entries DROP COLUMN command`); err != nil {
		return err
	}
	return tx.Commit()
}

// Package infrastructure — this file implements domain.UserRepository
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
	"log"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
	"github.com/openbastion/openbastion/services/access/authentication/migrations"
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
	res, err := migrate.Apply(ctx, db, "authentication", migrations.Files)
	if err != nil {
		db.Close()
		return nil, err
	}
	res.Log("authentication", log.Printf)
	return db, nil
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

// Create returns the exact same sentinel ErrUsernameTaken that
// InMemoryStore returns (defined once, in memory_store.go, and shared by
// both implementations of this package) — a caller must see identical
// behavior regardless of which storage engine is wired in, which is
// exactly what let the real bugs documented in NOTES_SANDBOX.md surface
// as test failures instead of silent divergence.
func (s *PostgresStore) Create(ctx context.Context, u *domain.User) error {
	roles := u.Roles
	if roles == nil {
		// pq.Array(nil) serializes a nil []string as SQL NULL, not as an
		// empty array — and the roles column is NOT NULL DEFAULT '{}'
		// (001_init.sql). InMemoryStore has no such constraint and
		// happily stores a nil slice, so a user created with no roles
		// yet (a legitimate case: an account pending a role grant)
		// compiled and passed every in-memory test, then failed outright
		// the first time it ran against a real database — exactly the
		// class of bug NOTES_SANDBOX.md already documents twice over for
		// this project. Normalizing to a non-nil, empty slice here keeps
		// Create's behavior identical across both storage engines.
		roles = []string{}
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO users (id, username, display_name, password_hash, roles, identity_source, external_subject)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		u.ID, u.Username, u.DisplayName, u.PasswordHash, pq.Array(roles), sourceOrLocal(u.IdentitySource), u.ExternalSubject)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique_violation
			return ErrUsernameTaken
		}
		return err
	}
	return nil
}

func (s *PostgresStore) GetByUsername(ctx context.Context, username string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, roles, identity_source, external_subject
		FROM users WHERE username = $1`, username)
	return scanUser(row)
}

func (s *PostgresStore) GetByID(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, roles, identity_source, external_subject
		FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, pq.Array(&u.Roles), &u.IdentitySource, &u.ExternalSubject); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

func sourceOrLocal(s string) string {
	if s == "" {
		return domain.SourceLocal
	}
	return s
}

// GetByExternalSubject is domain.UserRepository.GetByExternalSubject.
func (s *PostgresStore) GetByExternalSubject(ctx context.Context, source, subject string) (*domain.User, error) {
	if subject == "" {
		return nil, ErrUserNotFound
	}
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, roles, identity_source, external_subject
		FROM users WHERE identity_source = $1 AND external_subject = $2`, source, subject)
	return scanUser(row)
}

// UpdateIdentity is domain.UserRepository.UpdateIdentity.
func (s *PostgresStore) UpdateIdentity(ctx context.Context, id, displayName string, roles []string) error {
	if roles == nil {
		roles = []string{}
	}
	res, err := s.db.ExecContext(ctx, `UPDATE users SET display_name = $2, roles = $3 WHERE id = $1`, id, displayName, pq.Array(roles))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrUserNotFound
	}
	return nil
}

// SaveAttempt is domain.LoginAttemptRepository.SaveAttempt. It also drops the attempts past
// their end: they can never be taken.
func (s *PostgresStore) SaveAttempt(ctx context.Context, a domain.LoginAttempt) error {
	if _, err := s.db.ExecContext(ctx, `DELETE FROM oidc_login_attempts WHERE expires_at < now() - interval '1 hour'`); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO oidc_login_attempts (state, verifier, nonce, expires_at) VALUES ($1, $2, $3, $4)`,
		a.State, a.Verifier, a.Nonce, a.ExpiresAt)
	return err
}

// TakeAttempt is domain.LoginAttemptRepository.TakeAttempt: one DELETE … RETURNING, so that
// of two callbacks with the same state, one at most gets it — whichever replica they reach.
func (s *PostgresStore) TakeAttempt(ctx context.Context, state string) (domain.LoginAttempt, error) {
	var a domain.LoginAttempt
	err := s.db.QueryRowContext(ctx, `DELETE FROM oidc_login_attempts WHERE state = $1 RETURNING state, verifier, nonce, expires_at`, state).
		Scan(&a.State, &a.Verifier, &a.Nonce, &a.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return a, domain.ErrAttemptNotFound
	}
	return a, err
}

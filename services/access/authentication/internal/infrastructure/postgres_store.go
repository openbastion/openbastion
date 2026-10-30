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
		INSERT INTO users (id, username, display_name, password_hash, roles)
		VALUES ($1, $2, $3, $4, $5)`,
		u.ID, u.Username, u.DisplayName, u.PasswordHash, pq.Array(roles))
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
		SELECT id, username, display_name, password_hash, roles
		FROM users WHERE username = $1`, username)
	return scanUser(row)
}

func (s *PostgresStore) GetByID(ctx context.Context, id string) (*domain.User, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, username, display_name, password_hash, roles
		FROM users WHERE id = $1`, id)
	return scanUser(row)
}

func scanUser(row *sql.Row) (*domain.User, error) {
	var u domain.User
	if err := row.Scan(&u.ID, &u.Username, &u.DisplayName, &u.PasswordHash, pq.Array(&u.Roles)); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return &u, nil
}

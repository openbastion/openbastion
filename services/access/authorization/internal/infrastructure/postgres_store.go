// Package infrastructure — this file implements domain.PolicyRepository
// against a real PostgreSQL database (github.com/lib/pq — hosted directly
// on GitHub, no vanity-import resolution needed, unlike golang.org/x/*;
// see /NOTES_SANDBOX.md). Mirrors
// services/vault/password-vault/internal/infrastructure/postgres_store.go.
package infrastructure

import (
	"context"
	"database/sql"
	"errors"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/services/access/authorization/internal/domain"
	"github.com/openbastion/openbastion/services/access/authorization/migrations"
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

func (s *PostgresStore) Create(ctx context.Context, p *domain.Policy) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO policies (id, name, role, resource_pattern, effect, created_by, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())`,
		p.ID, p.Name, p.Role, p.ResourcePattern, string(p.Effect), p.CreatedBy)
	if err != nil {
		return err
	}
	return nil
}

// ForRoles uses pq.Array so a single query covers every role in roles,
// rather than one round trip per role — ForRoles is on CheckAccess's hot
// path (doc 06 §3), called on essentially every write and session request
// in the system.
func (s *PostgresStore) ForRoles(ctx context.Context, roles []string) ([]*domain.Policy, error) {
	if len(roles) == 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, role, resource_pattern, effect, created_by, created_at
		FROM policies WHERE role = ANY($1)`, pq.Array(roles))
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*domain.Policy
	for rows.Next() {
		var p domain.Policy
		var effect string
		var createdBy sql.NullString
		if err := rows.Scan(&p.ID, &p.Name, &p.Role, &p.ResourcePattern, &effect, &createdBy, &p.CreatedAt); err != nil {
			return nil, err
		}
		p.Effect = domain.Effect(effect)
		if createdBy.Valid {
			p.CreatedBy = createdBy.String
		}
		out = append(out, &p)
	}
	return out, rows.Err()
}

// Count backs AuthorizationService.BootstrapAdminPolicy — it must see the
// true, current row count, including rows written by another process
// against the same database, which is exactly why this is a real COUNT(*)
// and not anything cached.
func (s *PostgresStore) Count(ctx context.Context) (int, error) {
	var n int
	row := s.db.QueryRowContext(ctx, `SELECT count(*) FROM policies`)
	if err := row.Scan(&n); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return 0, nil
		}
		return 0, err
	}
	return n, nil
}

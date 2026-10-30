// Package infrastructure — this file implements domain.AccountRepository,
// domain.SecretRepository, and domain.ScopeRepository against a real
// PostgreSQL database (github.com/lib/pq — hosted directly on GitHub, no
// vanity-import resolution needed, unlike golang.org/x/*; see
// /NOTES_SANDBOX.md).
package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"log"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/pkg/migrate"
	"github.com/openbastion/openbastion/services/vault/password-vault/internal/domain"
	"github.com/openbastion/openbastion/services/vault/password-vault/migrations"
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
	res, err := migrate.Apply(ctx, db, "password-vault", migrations.Files)
	if err != nil {
		db.Close()
		return nil, err
	}
	res.Log("password-vault", log.Printf)
	return db, nil
}

type PostgresStore struct {
	db *sql.DB
}

func NewPostgresStore(db *sql.DB) *PostgresStore {
	return &PostgresStore{db: db}
}

func (s *PostgresStore) Create(ctx context.Context, a *domain.PrivilegedAccount) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO privileged_accounts (id, name, username, target_host, protocol, rotation_policy, created_at, reconciliation_account_id, host_key)
		VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8)`,
		a.ID, a.Name, a.Username, a.TargetHost, a.Protocol, string(a.RotationPolicy), a.ReconciliationAccountID, a.HostKey)
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*domain.PrivilegedAccount, error) {
	var a domain.PrivilegedAccount
	var rotationPolicy string
	var lastRotatedAt, disabledAt sql.NullTime
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, username, target_host, protocol, rotation_policy, last_rotated_at, created_at, disabled_at, reconciliation_account_id, host_key
		FROM privileged_accounts WHERE id = $1`, id)
	if err := row.Scan(&a.ID, &a.Name, &a.Username, &a.TargetHost, &a.Protocol, &rotationPolicy, &lastRotatedAt, &a.CreatedAt, &disabledAt, &a.ReconciliationAccountID, &a.HostKey); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	a.RotationPolicy = domain.RotationPolicy(rotationPolicy)
	if lastRotatedAt.Valid {
		a.LastRotatedAt = &lastRotatedAt.Time
	}
	if disabledAt.Valid {
		a.DisabledAt = &disabledAt.Time
	}
	return &a, nil
}

// List mirrors InMemoryStore.List: excludes disabled accounts, orders by
// id (doc 05 §2 names no sort order), paginates with LIMIT/OFFSET. page
// and pageSize are already validated/capped by the caller
// (application.VaultService.ListAccounts).
func (s *PostgresStore) List(ctx context.Context, page, pageSize int) ([]*domain.PrivilegedAccount, int, error) {
	var totalItems int
	if err := s.db.QueryRowContext(ctx,
		`SELECT count(*) FROM privileged_accounts WHERE disabled_at IS NULL`,
	).Scan(&totalItems); err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, username, target_host, protocol, rotation_policy, last_rotated_at, created_at, disabled_at, host_key
		FROM privileged_accounts WHERE disabled_at IS NULL
		ORDER BY id
		LIMIT $1 OFFSET $2`, pageSize, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	accounts := []*domain.PrivilegedAccount{}
	for rows.Next() {
		var a domain.PrivilegedAccount
		var rotationPolicy string
		var lastRotatedAt, disabledAt sql.NullTime
		if err := rows.Scan(&a.ID, &a.Name, &a.Username, &a.TargetHost, &a.Protocol, &rotationPolicy, &lastRotatedAt, &a.CreatedAt, &disabledAt, &a.HostKey); err != nil {
			return nil, 0, err
		}
		a.RotationPolicy = domain.RotationPolicy(rotationPolicy)
		if lastRotatedAt.Valid {
			a.LastRotatedAt = &lastRotatedAt.Time
		}
		if disabledAt.Valid {
			a.DisabledAt = &disabledAt.Time
		}
		accounts = append(accounts, &a)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return accounts, totalItems, nil
}

// Disable soft-deletes by setting disabled_at — see
// domain.AccountRepository.Disable's doc comment for why. Idempotent:
// re-disabling an already-disabled account just re-stamps the timestamp.
// Existence is checked by the caller (application.VaultService), not here.
func (s *PostgresStore) Disable(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE privileged_accounts SET disabled_at = now() WHERE id = $1`, id)
	return err
}

// MarkRotated sets last_rotated_at — see domain.AccountRepository.MarkRotated's
// doc comment for why this method exists (a real, previously-undiscovered
// gap of the same shape as Disable/disabled_at before it).
// SetHostKey is domain.AccountRepository.SetHostKey.
func (s *PostgresStore) SetHostKey(ctx context.Context, id, hostKey string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts SET host_key = $2 WHERE id = $1`, id, hostKey)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.ErrNotFound
	}
	return nil
}

// SetReconciliation is domain.AccountRepository.SetReconciliation.
func (s *PostgresStore) SetReconciliation(ctx context.Context, id, reconciliationID string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts SET reconciliation_account_id = $2 WHERE id = $1`, id, reconciliationID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.ErrNotFound
	}
	return nil
}

func (s *PostgresStore) MarkRotated(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE privileged_accounts SET last_rotated_at = now() WHERE id = $1`, id)
	return err
}

func (s *PostgresStore) CurrentVersion(ctx context.Context, accountID string) (*domain.SecretVersion, error) {
	var v domain.SecretVersion
	var supersededAt sql.NullTime
	row := s.db.QueryRowContext(ctx, `
		SELECT id, privileged_account_id, encrypted_material, encryption_key_id, version, created_at, superseded_at
		FROM vault_secrets WHERE privileged_account_id = $1 AND superseded_at IS NULL AND NOT pending`, accountID)
	if err := row.Scan(&v.ID, &v.PrivilegedAccountID, &v.EncryptedMaterial, &v.EncryptionKeyID, &v.Version, &v.CreatedAt, &supersededAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, domain.ErrNotFound
		}
		return nil, err
	}
	if supersededAt.Valid {
		v.SupersededAt = &supersededAt.Time
	}
	return &v, nil
}

func (s *PostgresStore) AddVersion(ctx context.Context, sv *domain.SecretVersion) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vault_secrets (id, privileged_account_id, encrypted_material, encryption_key_id, version, created_at)
		VALUES ($1, $2, $3, $4, $5, now())`,
		sv.ID, sv.PrivilegedAccountID, sv.EncryptedMaterial, sv.EncryptionKeyID, sv.Version)
	return err
}

func (s *PostgresStore) SupersedeCurrent(ctx context.Context, accountID string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE vault_secrets SET superseded_at = now()
		WHERE privileged_account_id = $1 AND superseded_at IS NULL AND NOT pending`, accountID)
	return err
}

// AddPending is domain.SecretRepository.AddPending; the partial unique index of
// 002_rotation.sql refuses a second pending version.
func (s *PostgresStore) AddPending(ctx context.Context, sv *domain.SecretVersion) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vault_secrets (id, privileged_account_id, encrypted_material, encryption_key_id, version, created_at, pending)
		VALUES ($1, $2, $3, $4, $5, now(), TRUE)`,
		sv.ID, sv.PrivilegedAccountID, sv.EncryptedMaterial, sv.EncryptionKeyID, sv.Version)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" {
		return domain.ErrRotationInProgress
	}
	return err
}

// PendingVersion is domain.SecretRepository.PendingVersion.
func (s *PostgresStore) PendingVersion(ctx context.Context, accountID string) (*domain.SecretVersion, error) {
	var v domain.SecretVersion
	err := s.db.QueryRowContext(ctx, `
		SELECT id, privileged_account_id, encrypted_material, encryption_key_id, version, created_at
		FROM vault_secrets WHERE privileged_account_id = $1 AND pending`, accountID).
		Scan(&v.ID, &v.PrivilegedAccountID, &v.EncryptedMaterial, &v.EncryptionKeyID, &v.Version, &v.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	v.Pending = true
	return &v, nil
}

// PromotePending is domain.SecretRepository.PromotePending: one transaction.
func (s *PostgresStore) PromotePending(ctx context.Context, accountID string, version int) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE vault_secrets SET superseded_at = now()
		WHERE privileged_account_id = $1 AND superseded_at IS NULL AND NOT pending`, accountID); err != nil {
		return err
	}
	res, err := tx.ExecContext(ctx, `UPDATE vault_secrets SET pending = FALSE
		WHERE privileged_account_id = $1 AND version = $2 AND pending`, accountID, version)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.ErrNotFound
	}
	return tx.Commit()
}

// DiscardPending is domain.SecretRepository.DiscardPending.
func (s *PostgresStore) DiscardPending(ctx context.Context, accountID string, version int) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM vault_secrets WHERE privileged_account_id = $1 AND version = $2 AND pending`, accountID, version)
	return err
}

func (s *PostgresStore) Save(ctx context.Context, g *domain.ScopeGrant) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO vault_scope_grants (token, session_id, privileged_account_id, proxy_service_id, expires_at, consumed, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, now())`,
		g.Token, g.SessionID, g.PrivilegedAccountID, g.ProxyServiceID, g.ExpiresAt, g.Consumed)
	return err
}

func (s *PostgresStore) ConsumeIfValid(ctx context.Context, token, callingProxyID string) (*domain.ScopeGrant, error) {
	var g domain.ScopeGrant
	row := s.db.QueryRowContext(ctx, `
		UPDATE vault_scope_grants
		SET consumed = true
		WHERE token = $1 AND consumed = false AND proxy_service_id = $2 AND expires_at > now()
		RETURNING token, session_id, privileged_account_id, proxy_service_id, expires_at, consumed`,
		token, callingProxyID)
	if err := row.Scan(&g.Token, &g.SessionID, &g.PrivilegedAccountID, &g.ProxyServiceID, &g.ExpiresAt, &g.Consumed); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, errors.New("scope token unknown, expired, already consumed, or not authorized for calling proxy")
		}
		return nil, err
	}
	return &g, nil
}

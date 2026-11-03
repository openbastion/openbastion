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
	"time"

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
		INSERT INTO privileged_accounts (id, name, username, target_host, protocol, rotation_policy, created_at, reconciliation_account_id, host_key, rotation_interval_days, approval_required, tls_certificate_sha256, target_domain)
		VALUES ($1, $2, $3, $4, $5, $6, now(), $7, $8, $9, $10, $11, $12)`,
		a.ID, a.Name, a.Username, a.TargetHost, a.Protocol, string(a.RotationPolicy), a.ReconciliationAccountID, a.HostKey, a.RotationIntervalDays, a.ApprovalRequired, a.TLSCertificateSHA256, a.TargetDomain)
	var pqErr *pq.Error
	if errors.As(err, &pqErr) && pqErr.Code == "23505" { // unique_violation
		return domain.ErrAlreadyExists
	}
	return err
}

func (s *PostgresStore) Get(ctx context.Context, id string) (*domain.PrivilegedAccount, error) {
	var a domain.PrivilegedAccount
	var rotationPolicy string
	var lastRotatedAt, disabledAt, attemptedAt, owedSince sql.NullTime
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, username, target_host, protocol, rotation_policy, last_rotated_at, created_at, disabled_at, reconciliation_account_id, host_key,
		       rotation_interval_days, rotation_attempted_at, rotation_failures, rotation_owed_since, approval_required, tls_certificate_sha256, target_domain
		FROM privileged_accounts WHERE id = $1`, id)
	if err := row.Scan(&a.ID, &a.Name, &a.Username, &a.TargetHost, &a.Protocol, &rotationPolicy, &lastRotatedAt, &a.CreatedAt, &disabledAt, &a.ReconciliationAccountID, &a.HostKey,
		&a.RotationIntervalDays, &attemptedAt, &a.RotationFailures, &owedSince, &a.ApprovalRequired, &a.TLSCertificateSHA256, &a.TargetDomain); err != nil {
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
	if attemptedAt.Valid {
		a.RotationAttemptedAt = &attemptedAt.Time
	}
	if owedSince.Valid {
		a.RotationOwedSince = &owedSince.Time
	}
	return &a, nil
}

// List mirrors InMemoryStore.List: excludes disabled accounts, orders by
// id (docs/api/rest/openapi.yaml names no sort order), paginates with LIMIT/OFFSET. page
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
		SELECT id, name, username, target_host, protocol, rotation_policy, last_rotated_at, created_at, disabled_at, host_key, rotation_interval_days, rotation_failures, approval_required, tls_certificate_sha256, target_domain
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
		if err := rows.Scan(&a.ID, &a.Name, &a.Username, &a.TargetHost, &a.Protocol, &rotationPolicy, &lastRotatedAt, &a.CreatedAt, &disabledAt, &a.HostKey, &a.RotationIntervalDays, &a.RotationFailures, &a.ApprovalRequired, &a.TLSCertificateSHA256, &a.TargetDomain); err != nil {
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

// SetApprovalRequired is domain.AccountRepository.SetApprovalRequired.
func (s *PostgresStore) SetApprovalRequired(ctx context.Context, id string, required bool) error {
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts SET approval_required = $2 WHERE id = $1`, id, required)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return domain.ErrNotFound
	}
	return nil
}

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

// SetTLSPin is domain.AccountRepository.SetTLSPin.
func (s *PostgresStore) SetTLSPin(ctx context.Context, id, fingerprint, targetDomain string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts SET tls_certificate_sha256 = $2, target_domain = $3 WHERE id = $1`, id, fingerprint, targetDomain)
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

// MarkRotated sets last_rotated_at — see domain.AccountRepository.MarkRotated's
// doc comment for why this method exists (a real, previously-undiscovered
// gap of the same shape as Disable/disabled_at before it).
func (s *PostgresStore) MarkRotated(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `
		UPDATE privileged_accounts SET last_rotated_at = now(), rotation_failures = 0, rotation_owed_since = NULL WHERE id = $1`, id)
	return err
}

// RecordRotationFailure is domain.AccountRepository.RecordRotationFailure: one UPDATE, so two
// Vaults never count the same failure as one.
func (s *PostgresStore) RecordRotationFailure(ctx context.Context, id string) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `UPDATE privileged_accounts SET rotation_failures = rotation_failures + 1
		WHERE id = $1 RETURNING rotation_failures`, id).Scan(&n)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, domain.ErrNotFound
	}
	return n, err
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

// The conditions of an account to be rotated at $1 and not taken since $2 (ADR-0040, ADR-0044):
// it owes a rotation, or its schedule is due. The time it has waited since orders them.
const (
	rotationDueAt  = `COALESCE(last_rotated_at, created_at) + rotation_interval_days * interval '1 day'`
	rotationWaited = `COALESCE(rotation_owed_since, ` + rotationDueAt + `)`
	notTaken       = `disabled_at IS NULL AND (rotation_attempted_at IS NULL OR rotation_attempted_at <= $2)`
	owed           = `rotation_owed_since IS NOT NULL`
	scheduleDue    = `(rotation_policy = 'scheduled' AND rotation_interval_days > 0 AND ` + rotationDueAt + ` <= $1)`
	dueForRotation = notTaken + ` AND (` + owed + ` OR ` + scheduleDue + `)`
	owedOnly       = notTaken + ` AND ` + owed + ` AND $1::timestamptz IS NOT NULL`
)

// ListDueForRotation is domain.AccountRepository.ListDueForRotation.
func (s *PostgresStore) ListDueForRotation(ctx context.Context, now time.Time, retryAfter time.Duration, limit int, scheduled bool) ([]*domain.PrivilegedAccount, error) {
	cond := owedOnly
	if scheduled {
		cond = dueForRotation
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id FROM privileged_accounts WHERE `+cond+`
		ORDER BY `+rotationWaited+`, id LIMIT $3`, now, now.Add(-retryAfter), limit)
	if err != nil {
		return nil, err
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return nil, err
		}
		ids = append(ids, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	due := make([]*domain.PrivilegedAccount, 0, len(ids))
	for _, id := range ids {
		a, err := s.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		due = append(due, a)
	}
	return due, nil
}

// MarkRotationOwed is domain.AccountRepository.MarkRotationOwed: the earliest date is kept.
func (s *PostgresStore) MarkRotationOwed(ctx context.Context, id string, at time.Time) error {
	// A new debt (none was owed) lifts the delay after an attempt — that delay is for failures;
	// a debt already owed, and failing, keeps it.
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts
		SET rotation_attempted_at = CASE WHEN rotation_owed_since IS NULL THEN NULL ELSE rotation_attempted_at END,
		    rotation_owed_since = LEAST(COALESCE(rotation_owed_since, $2), $2)
		WHERE id = $1`, id, at)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return domain.ErrNotFound
	}
	return nil
}

// ClaimRotation is domain.AccountRepository.ClaimRotation: one UPDATE, so that of two Vaults
// that list the same account, one takes it.
func (s *PostgresStore) ClaimRotation(ctx context.Context, id string, now time.Time, retryAfter time.Duration) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE privileged_accounts SET rotation_attempted_at = $1
		WHERE id = $3 AND `+dueForRotation, now, now.Add(-retryAfter), id)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

// SealedUnder is domain.SecretRepository.SealedUnder.
func (s *PostgresStore) SealedUnder(ctx context.Context, keyIDs []string, afterID string, limit int) ([]*domain.SecretVersion, error) {
	if len(keyIDs) == 0 || limit <= 0 {
		return nil, nil
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, privileged_account_id, encrypted_material, encryption_key_id, version
		FROM vault_secrets WHERE encryption_key_id = ANY($1) AND id > $2 ORDER BY id LIMIT $3`, pq.Array(keyIDs), afterID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*domain.SecretVersion
	for rows.Next() {
		var v domain.SecretVersion
		if err := rows.Scan(&v.ID, &v.PrivilegedAccountID, &v.EncryptedMaterial, &v.EncryptionKeyID, &v.Version); err != nil {
			return nil, err
		}
		out = append(out, &v)
	}
	return out, rows.Err()
}

// ResealIf is domain.SecretRepository.ResealIf: one UPDATE, conditional on the key still being
// the old one.
func (s *PostgresStore) ResealIf(ctx context.Context, versionID, oldKeyID string, material []byte, newKeyID string) (bool, error) {
	res, err := s.db.ExecContext(ctx, `
		UPDATE vault_secrets SET encrypted_material = $3, encryption_key_id = $4
		WHERE id = $1 AND encryption_key_id = $2`, versionID, oldKeyID, material, newKeyID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

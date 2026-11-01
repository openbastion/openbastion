package infrastructure

// domain.MFARepository (ADR-0062), in memory and in PostgreSQL (migration 003_mfa.sql).

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

type totpState struct {
	sealed []byte
	last   int64
}

type enrollmentCode struct {
	hash      []byte
	expiresAt time.Time
}

type memoryMFA struct {
	challenges map[string]domain.MFAChallenge         // by hex hash
	totp       map[string]totpState                   // by user id
	codes      map[string]enrollmentCode              // by source + "\x00" + name
	keys       map[string][]domain.WebAuthnCredential // by user id (ADR-0065)
}

func codeKey(source, name string) string { return source + "\x00" + name }

func (s *InMemoryStore) SaveChallenge(_ context.Context, c domain.MFAChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	c.Roles = append([]string(nil), c.Roles...)
	s.mfa.challenges[hex.EncodeToString(c.Hash)] = c
	return nil
}

func (s *InMemoryStore) GetChallenge(_ context.Context, hash []byte) (domain.MFAChallenge, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.mfa.challenges[hex.EncodeToString(hash)]
	if !ok {
		return c, domain.ErrChallengeNotFound
	}
	c.Roles = append([]string(nil), c.Roles...)
	return c, nil
}

func (s *InMemoryStore) FailChallenge(_ context.Context, hash []byte, max int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hex.EncodeToString(hash)
	c, ok := s.mfa.challenges[k]
	if !ok {
		return true, nil
	}
	c.Attempts++
	if c.Attempts >= max {
		delete(s.mfa.challenges, k)
		return true, nil
	}
	s.mfa.challenges[k] = c
	return false, nil
}

func (s *InMemoryStore) SetPendingSecret(_ context.Context, hash, sealed, codeHash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hex.EncodeToString(hash)
	c, ok := s.mfa.challenges[k]
	if !ok || c.PendingSecret != nil || (c.Kind == domain.MFAEnroll && c.WebAuthnSession != nil) {
		return false, nil
	}
	c.PendingSecret, c.EnrollmentCodeHash = append([]byte(nil), sealed...), append([]byte(nil), codeHash...)
	s.mfa.challenges[k] = c
	return true, nil
}

func (s *InMemoryStore) DeleteChallenge(_ context.Context, hash []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mfa.challenges, hex.EncodeToString(hash))
	return nil
}

func (s *InMemoryStore) TOTP(_ context.Context, userID string) ([]byte, int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t := s.mfa.totp[userID]
	return append([]byte(nil), t.sealed...), t.last, nil
}

func (s *InMemoryStore) SetTOTP(_ context.Context, userID string, sealed []byte, step int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.byID[userID]; !ok {
		return ErrUserNotFound
	}
	s.mfa.totp[userID] = totpState{sealed: append([]byte(nil), sealed...), last: step}
	return nil
}

func (s *InMemoryStore) AdvanceTOTPStep(_ context.Context, userID string, step int64) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.mfa.totp[userID]
	if !ok || t.sealed == nil || step <= t.last {
		return false, nil
	}
	t.last = step
	s.mfa.totp[userID] = t
	return true, nil
}

func (s *InMemoryStore) ResetTOTP(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mfa.totp, userID)
	return nil
}

func (s *InMemoryStore) SetPendingWebAuthn(_ context.Context, hash, session, codeHash []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := hex.EncodeToString(hash)
	c, ok := s.mfa.challenges[k]
	if !ok || c.PendingSecret != nil || c.WebAuthnSession != nil {
		return false, nil
	}
	c.WebAuthnSession, c.EnrollmentCodeHash = append([]byte(nil), session...), append([]byte(nil), codeHash...)
	s.mfa.challenges[k] = c
	return true, nil
}

func (s *InMemoryStore) WebAuthnCredentials(_ context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]domain.WebAuthnCredential(nil), s.mfa.keys[userID]...), nil
}

func (s *InMemoryStore) AddWebAuthnCredential(_ context.Context, userID string, c domain.WebAuthnCredential, max int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.mfa.keys[userID]) >= max {
		return false, nil
	}
	for _, keys := range s.mfa.keys {
		for _, k := range keys {
			if bytes.Equal(k.ID, c.ID) {
				return false, nil
			}
		}
	}
	s.mfa.keys[userID] = append(s.mfa.keys[userID], c)
	return true, nil
}

func (s *InMemoryStore) UpdateWebAuthnCredential(_ context.Context, userID string, c domain.WebAuthnCredential) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, k := range s.mfa.keys[userID] {
		if bytes.Equal(k.ID, c.ID) {
			c.CreatedAt = k.CreatedAt
			s.mfa.keys[userID][i] = c
			return nil
		}
	}
	return errors.New("no such security key")
}

func (s *InMemoryStore) ResetWebAuthn(_ context.Context, userID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.mfa.keys, userID)
	return nil
}

func (s *InMemoryStore) PutEnrollmentCode(_ context.Context, source, name string, hash []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mfa.codes[codeKey(source, name)] = enrollmentCode{hash: append([]byte(nil), hash...), expiresAt: expiresAt}
	return nil
}

func (s *InMemoryStore) EnrollmentCodeMatches(_ context.Context, source, name string, hash []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.mfa.codes[codeKey(source, name)]
	return ok && bytes.Equal(c.hash, hash) && now.Before(c.expiresAt), nil
}

func (s *InMemoryStore) TakeEnrollmentCode(_ context.Context, source, name string, hash []byte, now time.Time) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	k := codeKey(source, name)
	c, ok := s.mfa.codes[k]
	if !ok || !bytes.Equal(c.hash, hash) || !now.Before(c.expiresAt) {
		return false, nil
	}
	delete(s.mfa.codes, k)
	return true, nil
}

// -- PostgreSQL ----------------------------------------------------------------------------

func (s *PostgresStore) SaveChallenge(ctx context.Context, c domain.MFAChallenge) error {
	roles := c.Roles
	if roles == nil {
		roles = []string{}
	}
	_, err := s.db.ExecContext(ctx, `INSERT INTO mfa_challenges (challenge_hash, user_id, roles, kind, login_source, login_name, webauthn_session, attempts, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, 0, $8)`, c.Hash, c.UserID, pq.Array(roles), c.Kind, c.LoginSource, c.LoginName, c.WebAuthnSession, c.ExpiresAt.UTC())
	return err
}

func (s *PostgresStore) GetChallenge(ctx context.Context, hash []byte) (domain.MFAChallenge, error) {
	c := domain.MFAChallenge{Hash: hash}
	err := s.db.QueryRowContext(ctx, `SELECT user_id, roles, kind, login_source, login_name, pending_secret_enc, enrollment_code_hash, webauthn_session, attempts, expires_at
		FROM mfa_challenges WHERE challenge_hash = $1`, hash).Scan(&c.UserID, pq.Array(&c.Roles), &c.Kind, &c.LoginSource, &c.LoginName,
		&c.PendingSecret, &c.EnrollmentCodeHash, &c.WebAuthnSession, &c.Attempts, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return c, domain.ErrChallengeNotFound
	}
	return c, err
}

func (s *PostgresStore) FailChallenge(ctx context.Context, hash []byte, max int) (bool, error) {
	var attempts int
	err := s.db.QueryRowContext(ctx, `UPDATE mfa_challenges SET attempts = attempts + 1 WHERE challenge_hash = $1 RETURNING attempts`, hash).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if attempts >= max {
		_, err := s.db.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE challenge_hash = $1`, hash)
		return true, err
	}
	return false, nil
}

func (s *PostgresStore) SetPendingSecret(ctx context.Context, hash, sealed, codeHash []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET pending_secret_enc = $2, enrollment_code_hash = $3
		WHERE challenge_hash = $1 AND pending_secret_enc IS NULL AND NOT (kind = 'enrollment_required' AND webauthn_session IS NOT NULL)`, hash, sealed, codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *PostgresStore) DeleteChallenge(ctx context.Context, hash []byte) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mfa_challenges WHERE challenge_hash = $1`, hash)
	return err
}

func (s *PostgresStore) TOTP(ctx context.Context, userID string) ([]byte, int64, error) {
	var sealed []byte
	var last int64
	err := s.db.QueryRowContext(ctx, `SELECT totp_secret_enc, totp_last_step FROM users WHERE id = $1`, userID).Scan(&sealed, &last)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, 0, ErrUserNotFound
	}
	return sealed, last, err
}

func (s *PostgresStore) SetTOTP(ctx context.Context, userID string, sealed []byte, step int64) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret_enc = $2, totp_last_step = $3 WHERE id = $1`, userID, sealed, step)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return ErrUserNotFound
	}
	return nil
}

func (s *PostgresStore) AdvanceTOTPStep(ctx context.Context, userID string, step int64) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET totp_last_step = $2
		WHERE id = $1 AND totp_secret_enc IS NOT NULL AND totp_last_step < $2`, userID, step)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *PostgresStore) ResetTOTP(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET totp_secret_enc = NULL, totp_last_step = 0 WHERE id = $1`, userID)
	return err
}

func (s *PostgresStore) PutEnrollmentCode(ctx context.Context, source, name string, hash []byte, expiresAt time.Time) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO mfa_enrollment_codes (login_source, login_name, code_hash, expires_at) VALUES ($1, $2, $3, $4)
		ON CONFLICT (login_source, login_name) DO UPDATE SET code_hash = EXCLUDED.code_hash, expires_at = EXCLUDED.expires_at, created_at = now()`,
		source, name, hash, expiresAt.UTC())
	return err
}

func (s *PostgresStore) EnrollmentCodeMatches(ctx context.Context, source, name string, hash []byte, now time.Time) (bool, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT count(*) FROM mfa_enrollment_codes
		WHERE login_source = $1 AND login_name = $2 AND code_hash = $3 AND expires_at > $4`, source, name, hash, now.UTC()).Scan(&n)
	return n == 1, err
}

func (s *PostgresStore) TakeEnrollmentCode(ctx context.Context, source, name string, hash []byte, now time.Time) (bool, error) {
	res, err := s.db.ExecContext(ctx, `DELETE FROM mfa_enrollment_codes
		WHERE login_source = $1 AND login_name = $2 AND code_hash = $3 AND expires_at > $4`, source, name, hash, now.UTC())
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *PostgresStore) SetPendingWebAuthn(ctx context.Context, hash, session, codeHash []byte) (bool, error) {
	res, err := s.db.ExecContext(ctx, `UPDATE mfa_challenges SET webauthn_session = $2, enrollment_code_hash = $3
		WHERE challenge_hash = $1 AND pending_secret_enc IS NULL AND webauthn_session IS NULL`, hash, session, codeHash)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *PostgresStore) WebAuthnCredentials(ctx context.Context, userID string) ([]domain.WebAuthnCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT credential_id, credential, sign_count, created_at FROM mfa_webauthn_credentials
		WHERE user_id = $1 ORDER BY created_at, credential_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []domain.WebAuthnCredential
	for rows.Next() {
		var c domain.WebAuthnCredential
		var count int64
		if err := rows.Scan(&c.ID, &c.Data, &count, &c.CreatedAt); err != nil {
			return nil, err
		}
		c.SignCount = uint32(count)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) AddWebAuthnCredential(ctx context.Context, userID string, c domain.WebAuthnCredential, max int) (bool, error) {
	res, err := s.db.ExecContext(ctx, `INSERT INTO mfa_webauthn_credentials (credential_id, user_id, credential, sign_count)
		SELECT $1, $2, $3, $4 WHERE (SELECT count(*) FROM mfa_webauthn_credentials WHERE user_id = $2) < $5
		ON CONFLICT (credential_id) DO NOTHING`, c.ID, userID, c.Data, int64(c.SignCount), max)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}

func (s *PostgresStore) UpdateWebAuthnCredential(ctx context.Context, userID string, c domain.WebAuthnCredential) error {
	res, err := s.db.ExecContext(ctx, `UPDATE mfa_webauthn_credentials SET credential = $3, sign_count = $4
		WHERE credential_id = $1 AND user_id = $2`, c.ID, userID, c.Data, int64(c.SignCount))
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n != 1 {
		return errors.New("no such security key")
	}
	return nil
}

func (s *PostgresStore) ResetWebAuthn(ctx context.Context, userID string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM mfa_webauthn_credentials WHERE user_id = $1`, userID)
	return err
}

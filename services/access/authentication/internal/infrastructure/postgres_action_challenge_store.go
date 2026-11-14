package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

func (s *PostgresStore) SaveActionChallenge(ctx context.Context, challenge domain.MFAActionChallenge) error {
	if err := challenge.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mfa_action_challenges
			(challenge_hash, user_id, session_id, account_id, protocol, action,
			 factors, webauthn_session, attempts, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,0,$9)`,
		challenge.Hash, challenge.Binding.UserID, challenge.Binding.SessionID,
		challenge.Binding.AccountID, challenge.Binding.Protocol, challenge.Binding.Action,
		pq.Array(challenge.Factors), challenge.WebAuthnSession, challenge.ExpiresAt.UTC())
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return domain.ErrMFAActionGrantExists
		}
	}
	return err
}

func (s *PostgresStore) GetActionChallenge(ctx context.Context, hash []byte) (domain.MFAActionChallenge, error) {
	c := domain.MFAActionChallenge{Hash: append([]byte(nil), hash...)}
	err := s.db.QueryRowContext(ctx, `
		SELECT user_id, session_id, account_id, protocol, action, factors,
		       webauthn_session, attempts, expires_at
		  FROM mfa_action_challenges WHERE challenge_hash = $1`, hash).Scan(
		&c.Binding.UserID, &c.Binding.SessionID, &c.Binding.AccountID,
		&c.Binding.Protocol, &c.Binding.Action, pq.Array(&c.Factors),
		&c.WebAuthnSession, &c.Attempts, &c.ExpiresAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.MFAActionChallenge{}, domain.ErrChallengeNotFound
	}
	return c, err
}

func (s *PostgresStore) FailActionChallenge(ctx context.Context, hash []byte, max int) (bool, error) {
	var attempts int
	err := s.db.QueryRowContext(ctx, `
		UPDATE mfa_action_challenges
		   SET attempts = attempts + 1
		 WHERE challenge_hash = $1
		RETURNING attempts`, hash).Scan(&attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return true, nil
	}
	if err != nil {
		return false, err
	}
	if attempts < max {
		return false, nil
	}
	_, err = s.db.ExecContext(ctx, `DELETE FROM mfa_action_challenges WHERE challenge_hash = $1`, hash)
	return true, err
}

func (s *PostgresStore) ConsumeActionChallenge(ctx context.Context, hash []byte, now time.Time) (bool, error) {
	var consumed []byte
	err := s.db.QueryRowContext(ctx, `
		DELETE FROM mfa_action_challenges
		 WHERE challenge_hash = $1 AND expires_at > $2
		RETURNING challenge_hash`, hash, now.UTC()).Scan(&consumed)
	if errors.Is(err, sql.ErrNoRows) {
		_, cleanupErr := s.db.ExecContext(ctx,
			`DELETE FROM mfa_action_challenges WHERE challenge_hash = $1 AND expires_at <= $2`, hash, now.UTC())
		return false, cleanupErr
	}
	if err != nil {
		return false, err
	}
	return len(consumed) == len(hash), nil
}

package infrastructure

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/lib/pq"

	"github.com/openbastion/openbastion/services/access/authentication/internal/domain"
)

// SaveActionGrant persists only the digest of an opaque, random action grant.
func (s *PostgresStore) SaveActionGrant(ctx context.Context, grant domain.MFAActionGrant) error {
	if err := grant.Validate(); err != nil {
		return err
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO mfa_action_grants
			(grant_hash, user_id, session_id, account_id, protocol, action, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		grant.Hash, grant.UserID, grant.SessionID, grant.AccountID,
		grant.Protocol, grant.Action, grant.ExpiresAt.UTC())
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code == "23505" {
			return domain.ErrMFAActionGrantExists
		}
	}
	return err
}

// ConsumeActionGrant atomically consumes a grant only when its full context
// matches and it has not expired or already been consumed. UPDATE ... RETURNING
// is the cross-replica compare-and-swap; at most one concurrent caller wins.
func (s *PostgresStore) ConsumeActionGrant(ctx context.Context, hash []byte, expected domain.MFAActionGrantBinding, now time.Time) (bool, error) {
	if len(hash) != 32 || expected.Validate() != nil {
		return false, nil
	}
	var consumedHash []byte
	err := s.db.QueryRowContext(ctx, `
		UPDATE mfa_action_grants
		   SET consumed_at = $7
		 WHERE grant_hash = $1
		   AND user_id = $2
		   AND session_id = $3
		   AND account_id = $4
		   AND protocol = $5
		   AND action = $6
		   AND consumed_at IS NULL
		   AND expires_at > $7
		RETURNING grant_hash`,
		hash, expected.UserID, expected.SessionID, expected.AccountID,
		expected.Protocol, expected.Action, now.UTC()).Scan(&consumedHash)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return len(consumedHash) == len(hash), nil
}

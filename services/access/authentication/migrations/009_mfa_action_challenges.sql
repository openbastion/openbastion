-- ADR-0097: a distinct MFA ceremony for one privileged-session action.
-- Challenge and grant values are opaque random values; only SHA-256 digests are persisted.
CREATE TABLE IF NOT EXISTS mfa_action_challenges (
    challenge_hash   BYTEA PRIMARY KEY CHECK (octet_length(challenge_hash) = 32),
    user_id          TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id       TEXT NOT NULL,
    account_id       TEXT NOT NULL,
    protocol         TEXT NOT NULL CHECK (protocol IN ('ssh', 'vnc', 'rdp')),
    action           TEXT NOT NULL CHECK (action IN ('secret:inject', 'secret:paste')),
    factors          TEXT[] NOT NULL,
    webauthn_session BYTEA,
    attempts         INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    expires_at       TIMESTAMPTZ NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_action_challenges_expires_idx ON mfa_action_challenges (expires_at);

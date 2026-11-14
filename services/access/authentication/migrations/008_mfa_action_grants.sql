-- ADR-0097: a fresh MFA proof grants one exact session action, not a login token.
-- The opaque grant itself is never stored; only its SHA-256 and binding context are kept.
CREATE TABLE IF NOT EXISTS mfa_action_grants (
    grant_hash  BYTEA PRIMARY KEY CHECK (octet_length(grant_hash) = 32),
    user_id     TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
    session_id  TEXT NOT NULL,
    account_id  TEXT NOT NULL,
    protocol    TEXT NOT NULL CHECK (protocol IN ('ssh', 'vnc', 'rdp')),
    action      TEXT NOT NULL CHECK (action IN ('secret:inject', 'secret:paste')),
    expires_at  TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_action_grants_expires_idx ON mfa_action_grants (expires_at);

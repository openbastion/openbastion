-- ADR-0138: Authentication is the authority for whether an identity is active.
-- Existing users remain active; disabling an identity is represented by a timestamp.
ALTER TABLE users ADD COLUMN IF NOT EXISTS disabled_at TIMESTAMPTZ;

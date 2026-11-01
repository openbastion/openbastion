-- ADR-0062 : le second facteur TOTP. Le secret de chaque compte, scellé (AES-256-GCM sous
-- MFA_SECRET_KEY_HEX, lié à l'identifiant du compte) : la base seule ne le lit pas. Le dernier
-- pas accepté : un code ne sert qu'une fois.
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_secret_enc BYTEA;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;

-- Le second temps d'une connexion dont le mot de passe était bon : par l'empreinte SHA-256 du
-- défi, jamais le défi lui-même ; 5 minutes, 5 essais.
CREATE TABLE IF NOT EXISTS mfa_challenges (
    challenge_hash       BYTEA PRIMARY KEY,
    user_id              TEXT NOT NULL,
    roles                TEXT[] NOT NULL DEFAULT '{}',
    kind                 TEXT NOT NULL CHECK (kind IN ('required', 'enrollment_required')),
    login_source         TEXT NOT NULL,
    login_name           TEXT NOT NULL,
    pending_secret_enc   BYTEA,
    enrollment_code_hash BYTEA,
    attempts             INTEGER NOT NULL DEFAULT 0,
    expires_at           TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS mfa_challenges_expires_idx ON mfa_challenges (expires_at);

-- Les codes d'enrôlement qu'un administrateur émet : un par nom de connexion et par source, par
-- son empreinte, 24 heures, à usage unique.
CREATE TABLE IF NOT EXISTS mfa_enrollment_codes (
    login_source TEXT NOT NULL,
    login_name   TEXT NOT NULL,
    code_hash    BYTEA NOT NULL,
    expires_at   TIMESTAMPTZ NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (login_source, login_name)
);

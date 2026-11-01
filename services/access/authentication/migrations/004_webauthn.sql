-- ADR-0065 : WebAuthn, second facteur qui résiste à l'hameçonnage. La cérémonie en cours d'un
-- défi, et les clés de sécurité de chaque compte : des clés publiques, pas des secrets.
ALTER TABLE mfa_challenges ADD COLUMN IF NOT EXISTS webauthn_session BYTEA;

CREATE TABLE IF NOT EXISTS mfa_webauthn_credentials (
    credential_id BYTEA PRIMARY KEY,
    user_id       TEXT NOT NULL,
    credential    BYTEA NOT NULL,          -- la clé publique, ses drapeaux, son AAGUID, tels que le vérificateur les garde
    sign_count    BIGINT NOT NULL DEFAULT 0,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS mfa_webauthn_credentials_user_idx ON mfa_webauthn_credentials (user_id);

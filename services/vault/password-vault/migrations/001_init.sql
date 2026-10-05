-- Password Vault — schéma PostgreSQL initial. Suit OpenBastion_06 §3, avec
-- deux écarts assumés : (1) identifiants TEXT fournis par l'appelant, pas
-- des UUID générés ; (2) vault_scope_grants n'existait pas dans le doc 06,
-- ajoutée en cohérence avec domain.ScopeGrant.

CREATE TABLE IF NOT EXISTS privileged_accounts (
    id               TEXT PRIMARY KEY,
    name             TEXT NOT NULL,
    username         TEXT NOT NULL,
    target_host      TEXT NOT NULL,
    protocol         TEXT NOT NULL,
    rotation_policy  TEXT NOT NULL,
    last_rotated_at  TIMESTAMPTZ,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    disabled_at      TIMESTAMPTZ,
    UNIQUE (target_host, name)
);

CREATE TABLE IF NOT EXISTS vault_secrets (
    id                     TEXT PRIMARY KEY,
    privileged_account_id  TEXT NOT NULL REFERENCES privileged_accounts(id) ON DELETE CASCADE,
    encrypted_material     BYTEA NOT NULL,
    encryption_key_id      TEXT NOT NULL,
    version                INT NOT NULL,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now(),
    superseded_at          TIMESTAMPTZ,
    UNIQUE (privileged_account_id, version)
);

CREATE INDEX IF NOT EXISTS idx_vault_secrets_current
    ON vault_secrets (privileged_account_id) WHERE superseded_at IS NULL;

CREATE TABLE IF NOT EXISTS vault_scope_grants (
    token                  TEXT PRIMARY KEY,
    session_id             TEXT NOT NULL,
    privileged_account_id  TEXT NOT NULL REFERENCES privileged_accounts(id) ON DELETE CASCADE,
    proxy_service_id       TEXT NOT NULL,
    expires_at             TIMESTAMPTZ NOT NULL,
    consumed               BOOLEAN NOT NULL DEFAULT false,
    created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vault_scope_grants_account
    ON vault_scope_grants (privileged_account_id);

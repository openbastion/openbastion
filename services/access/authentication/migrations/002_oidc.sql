-- ADR-0035 : la connexion fédérée OIDC. Qui répond d'un compte (`identity_source`, doc 06 :
-- 'local' ou 'oidc') et, pour un compte OIDC, le `sub` du fournisseur. Un compte local garde
-- 'local' et un sujet vide ; un compte OIDC n'a pas de mot de passe (password_hash vide : la
-- connexion locale le refuse).
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_source TEXT NOT NULL DEFAULT 'local';
ALTER TABLE users ADD COLUMN IF NOT EXISTS external_subject TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS users_external_subject_idx ON users (identity_source, external_subject) WHERE external_subject <> '';

-- Les connexions fédérées en cours : ce que le retour du fournisseur doit retrouver, une fois.
CREATE TABLE IF NOT EXISTS oidc_login_attempts (
    state       TEXT PRIMARY KEY,
    verifier    TEXT NOT NULL,
    nonce       TEXT NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS oidc_login_attempts_expires_idx ON oidc_login_attempts (expires_at);

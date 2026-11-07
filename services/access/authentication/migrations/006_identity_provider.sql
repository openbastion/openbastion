-- ADR-0076 : plusieurs fournisseurs d'identité à la fois, chaque compte lié au sien. Un `sub` OIDC
-- n'est unique que chez son émetteur : le compte est retrouvé par (source, fournisseur, sujet).
-- Les comptes existants ont le fournisseur '' : celui des variables OIDC_* et LDAP_*, ou celui
-- qu'une entrée de IDENTITY_PROVIDERS_FILE déclare reprendre. Aucune ligne n'est réécrite.
ALTER TABLE users ADD COLUMN IF NOT EXISTS identity_provider TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS users_external_identity_idx ON users (identity_source, identity_provider, external_subject) WHERE external_subject <> '';
DROP INDEX IF EXISTS users_external_subject_idx;

-- Une connexion OIDC en cours retient son fournisseur : le retour ne s'échange que chez lui.
ALTER TABLE oidc_login_attempts ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT '';

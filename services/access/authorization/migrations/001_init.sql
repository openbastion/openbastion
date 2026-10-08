-- Authorization Service — schéma PostgreSQL initial. Suit
-- OpenBastion_06_Modele_Donnees.md §3 (table policies), avec le même
-- écart assumé que password-vault/migrations/001_init.sql : identifiants
-- TEXT fournis par l'appelant, pas des UUID générés côté serveur, et
-- "role" est stocké comme un nom de rôle brut (TEXT), pas une clé
-- étrangère vers une table roles — ce service ne gère pas lui-même le
-- cycle de vie des rôles, qui restent des attributs fédérés par l'IdP
-- (ADR-0007, JWT roles claim), pas une entité locale en MVP. Voir
-- NOTES_SANDBOX.md pour le détail des deux écarts.

CREATE TABLE IF NOT EXISTS policies (
    id                TEXT PRIMARY KEY,
    name              TEXT NOT NULL,
    role              TEXT NOT NULL,
    resource_pattern  TEXT NOT NULL,
    effect            TEXT NOT NULL CHECK (effect IN ('allow','deny')),
    created_by        TEXT,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (role, resource_pattern, effect)
);

CREATE INDEX IF NOT EXISTS idx_policies_role ON policies (role);

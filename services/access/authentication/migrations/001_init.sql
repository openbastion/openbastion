-- Authentication Service — schéma PostgreSQL initial. Suit
-- OpenBastion_06_Modele_Donnees.md §3 (table users), avec les mêmes
-- écarts assumés que partout ailleurs dans ce sandbox (voir
-- NOTES_SANDBOX.md) et déjà documentés dans internal/domain/user.go :
--
--   1. Identifiant TEXT fourni par l'appelant (application.randomID),
--      pas de UUID généré côté serveur.
--   2. Pas de table roles/user_roles séparée — les rôles sont stockés
--      directement comme un tableau de noms sur la ligne utilisateur ;
--      Authorization possède déjà ce qu'un rôle PEUT faire (policies),
--      Authentication possède seulement qui a quel rôle. Voir user.go
--      pour le rationale complet.
--   3. Pas de colonnes identity_source/external_subject — ce MVP ne
--      couvre que l'identité locale (doc 04 §2) ; l'intégration
--      LDAP/AD/Entra ID/OIDC/SAML reste hors périmètre MVP.

CREATE TABLE IF NOT EXISTS users (
    id             TEXT PRIMARY KEY,
    username       TEXT NOT NULL UNIQUE,
    display_name   TEXT NOT NULL,
    password_hash  TEXT NOT NULL,
    roles          TEXT[] NOT NULL DEFAULT '{}',
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

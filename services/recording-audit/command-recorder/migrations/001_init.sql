-- Command Recorder — schéma PostgreSQL. Suit OpenBastion_06_Modele_Donnees.md
-- §3 (table session_command_entries), avec les écarts assumés suivants :
--
--   1. `session_id` est un TEXT fourni par l'appelant, pas un UUID.
--   2. Pas de clé étrangère vers `sessions(id)` ni de `ON DELETE CASCADE` :
--      `sessions` appartient à la base du Session Broker, et une base par
--      service ne PEUT physiquement pas poser de FK inter-services. La
--      conséquence voulue : supprimer une session ne détruirait jamais son
--      enregistrement — et ce service n'expose de toute façon ni UPDATE ni
--      DELETE (domain.CommandRepository est en ajout seul).
--   3. La commande n'est JAMAIS stockée en clair : `command_sealed` contient
--      le texte chiffré (AES-256-GCM, nonce en préfixe) sous la clé de données
--      de la session, elle-même stockée enveloppée dans
--      `session_recording_keys` — voir infrastructure/envelope.go. Le doc 06
--      prévoit une colonne `command TEXT` ; elle n'existe plus dans ce schéma.
--      Une base créée avant le chiffrement (colonne `command` présente) est
--      migrée au démarrage par PostgresStore (chiffrement des lignes, puis
--      suppression de la colonne) : voir sealLegacyPlaintext.
--
-- L'index couvre exactement la requête de replay : les entrées d'une
-- session, dans l'ordre (ts, id).

CREATE TABLE IF NOT EXISTS session_recording_keys (
    session_id   TEXT PRIMARY KEY,
    kek_id       TEXT NOT NULL,       -- quelle clé KEK a enveloppé cette DEK (rotation future)
    wrapped_dek  BYTEA NOT NULL,      -- jamais la DEK en clair
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS session_command_entries (
    id              BIGSERIAL PRIMARY KEY,
    session_id      TEXT NOT NULL,
    ts              TIMESTAMPTZ NOT NULL,
    command_sealed  BYTEA NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_session_command_entries_session ON session_command_entries (session_id, ts, id);
